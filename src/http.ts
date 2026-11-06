import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createServer } from './server.js';
import { runWithCredentials } from './client.js';
import { logger } from './utils/logger.js';
import { MAX_REQUEST_BODY_BYTES } from './input-limits.js';
import { verifyS2sHeader, S2S_HEADER } from './s2s-verify.js';

/**
 * Public example values. A copied placeholder must not verify as a real
 * secret and must not be treated as "enforcement disabled".
 */
const KNOWN_PLACEHOLDER_SECRETS = new Set([
  'replace-with-a-real-secret',
  'your-s2s-secret',
  'your-secret',
  'changeme',
  'change-me',
  'placeholder',
  'secret',
  'example',
  'replace-me',
  's2s-secret',
]);

const MISSING_S2S_SECRET_ERROR =
  'Refusing to start HTTP server: CONDUIT_S2S_SECRET is empty. ' +
  'Set CONDUIT_S2S_SECRET to the gateway-provisioned secret (openssl rand -hex 32), or set MCP_ALLOW_INSECURE_DEV=1 for local development only.';

const PLACEHOLDER_S2S_SECRET_ERROR =
  'Refusing to start HTTP server: CONDUIT_S2S_SECRET is a known placeholder. ' +
  'Generate a secret with `openssl rand -hex 32` and set CONDUIT_S2S_SECRET to that value.';

const INSECURE_DEV_WARNING =
  'SECURITY WARNING: CONDUIT_S2S_SECRET is unset and MCP_ALLOW_INSECURE_DEV=1. ' +
  'HTTP /mcp is starting with service-to-service authentication DISABLED, bound to 127.0.0.1 only. ' +
  'Local development only; do not expose this port.';

const INSECURE_DEV_NON_LOOPBACK_ERROR =
  'Refusing to start HTTP server: MCP_ALLOW_INSECURE_DEV=1 without CONDUIT_S2S_SECRET only binds 127.0.0.1. ' +
  'Unset MCP_HTTP_HOST or set it to 127.0.0.1.';

const LOOPBACK_HOST = '127.0.0.1';

const S2S_UNAUTHORIZED = {
  error: 'Missing or invalid X-Gateway-S2S header: this endpoint only accepts requests signed by the gateway.',
};

const GATEWAY_CREDENTIALS_UNAUTHORIZED = {
  error: 'Unauthorized: missing required gateway credential header X-Petra-Api-Key.',
};

function headerValue(value: string | string[] | undefined): string | undefined {
  const raw = Array.isArray(value) ? value[0] : value;
  if (typeof raw !== 'string') return undefined;
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function isLoopbackHost(host: string): boolean {
  const normalized = host.trim().toLowerCase();
  if (normalized === 'localhost' || normalized === '::1' || normalized === '[::1]') return true;
  const bare = normalized.startsWith('::ffff:') ? normalized.slice('::ffff:'.length) : normalized;
  const parts = bare.split('.');
  if (parts.length !== 4) return false;
  if (parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return false;
  return parts[0] === '127';
}

/**
 * Fail closed. Read at HTTP startup, not at module load, so an empty
 * CONDUIT_S2S_SECRET cannot be frozen in as "enforcement disabled".
 * A known placeholder always refuses to start, including when
 * MCP_ALLOW_INSECURE_DEV=1. The secret value is never logged.
 * Returns whether this process is the insecure-dev bypass (no real secret).
 */
function resolveS2sStartup(): { secret: string; insecureDev: boolean } {
  const raw = (process.env.CONDUIT_S2S_SECRET ?? '').trim();
  if (KNOWN_PLACEHOLDER_SECRETS.has(raw.toLowerCase())) {
    logger.error(PLACEHOLDER_S2S_SECRET_ERROR);
    process.exit(1);
  }
  if (raw) return { secret: raw, insecureDev: false };
  if (process.env.MCP_ALLOW_INSECURE_DEV === '1') {
    // error level so LOG_LEVEL=warn|error cannot hide the bypass.
    logger.error(INSECURE_DEV_WARNING);
    return { secret: '', insecureDev: true };
  }
  logger.error(MISSING_S2S_SECRET_ERROR);
  process.exit(1);
}

/**
 * No secret (only reachable via MCP_ALLOW_INSECURE_DEV=1) forces 127.0.0.1.
 * Loopback names such as localhost and ::1 are rewritten to that address.
 * Any other host refuses to start. A configured secret honors MCP_HTTP_HOST,
 * and an unset host still defaults to 127.0.0.1.
 */
function resolveBindHost(insecureDev: boolean): string {
  const configured = (process.env.MCP_HTTP_HOST ?? '').trim();
  if (!insecureDev) {
    return configured === '' ? LOOPBACK_HOST : configured;
  }
  if (configured === '' || isLoopbackHost(configured)) return LOOPBACK_HOST;
  logger.error(INSECURE_DEV_NON_LOOPBACK_ERROR);
  process.exit(1);
}

export async function startHttpServer(): Promise<Server> {
  const { secret, insecureDev } = resolveS2sStartup();
  const port = parseInt(process.env.MCP_HTTP_PORT || '8080', 10);
  const host = resolveBindHost(insecureDev);
  const isGatewayMode = process.env.AUTH_MODE === 'gateway';

  const handleRequest = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    // Parse against a fixed base so a malformed Host header cannot make
    // new URL() throw before routing. Only the path is used.
    let url: URL;
    try {
      url = new URL(req.url || '/', 'http://localhost');
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Bad request URL' }));
      return;
    }

    // /health is container LIVENESS, not credential-readiness. Unauthenticated,
    // and it must not read credentials: gateway mode has none at process scope,
    // and reading them would reveal whether env credentials are configured.
    if (url.pathname === '/health' || url.pathname === '/healthz') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          status: 'ok',
          transport: 'http',
          mode: isGatewayMode ? 'gateway' : 'standalone',
          timestamp: new Date().toISOString(),
        })
      );
      return;
    }

    if (url.pathname !== '/mcp') {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found', endpoints: ['/mcp', '/health', '/healthz'] }));
      return;
    }

    // Conduit service-to-service auth (gateway#377 parity): rejected BEFORE
    // any credential extraction. An empty secret only reaches this point when
    // MCP_ALLOW_INSECURE_DEV=1, in which case there is nothing to verify.
    if (secret && !verifyS2sHeader(headerValue(req.headers[S2S_HEADER]), secret)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(S2S_UNAUTHORIZED));
      return;
    }

    // Credentials must arrive on every request in gateway mode. Falling
    // through would resolve PETRA_API_KEY from the process environment, which
    // is not request-scoped and would let anyone who can reach the port use the
    // container's vendor credentials. Checked before the body cap so a missing
    // credential is 401, never 413.
    let apiKey: string | undefined;
    if (isGatewayMode) {
      apiKey = headerValue(req.headers['x-petra-api-key']);
      if (!apiKey) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(GATEWAY_CREDENTIALS_UNAUTHORIZED));
        return;
      }
    }

    // Body cap runs only after the S2S and gateway credential checks so unauthenticated callers still get 401.
    const contentLength = Number(headerValue(req.headers['content-length']));
    if (Number.isFinite(contentLength) && contentLength > MAX_REQUEST_BODY_BYTES) {
      res.writeHead(413, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          error: { code: -32600, message: `Request body exceeds ${MAX_REQUEST_BODY_BYTES} bytes` },
          id: null,
        })
      );
      return;
    }

    const handle = async () => {
      // SECURITY-CRITICAL invariant: this transport MUST stay stateless
      // (sessionIdGenerator: undefined + enableJsonResponse: true).
      // Per-request tenant credentials are carried in an AsyncLocalStorage
      // context opened by runWithCredentials() below. A stateless
      // request->single-response flow keeps the tool call inside that
      // context - switching to a stateful/SSE transport would let a
      // long-lived connection serve later messages under a stale/foreign
      // credential context.
      const server = createServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
        maxRequestBodySize: MAX_REQUEST_BODY_BYTES,
      });
      res.on('close', () => {
        transport.close();
        server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res);
    };

    if (apiKey) {
      await runWithCredentials({ apiKey }, handle);
      return;
    }

    await handle();
  };

  const httpServer = createHttpServer((req, res) => {
    // A rejected handler must never become an unhandled rejection, which
    // would take the process down.
    handleRequest(req, res).catch((error: unknown) => {
      logger.error('Unhandled HTTP request error', {
        error: error instanceof Error ? error.message : String(error),
      });
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal server error' }));
      } else {
        res.end();
      }
    });
  });

  return new Promise((resolve, reject) => {
    httpServer.once('error', reject);
    httpServer.listen(port, host, () => {
      const bound = httpServer.address();
      const shown = bound && typeof bound !== 'string' ? `${bound.address}:${bound.port}` : `${host}:${port}`;
      logger.info(`HTTP streaming server listening on ${shown}`);
      resolve(httpServer);
    });
  });
}

// Vitest imports this module to call startHttpServer. Skip the CLI
// entrypoint there. `node dist/http.js` still starts HTTP or falls through
// to stdio. stdio does not use CONDUIT_S2S_SECRET.
if (process.env.VITEST !== 'true') {
  const transport = process.env.MCP_TRANSPORT;
  if (transport === 'http') {
    startHttpServer().catch((error) => {
      logger.error('Fatal startup error', {
        error: error instanceof Error ? error.message : String(error),
      });
      process.exit(1);
    });
  } else {
    import('./index.js');
  }
}

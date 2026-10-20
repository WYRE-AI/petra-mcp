/**
 * HTTP transport fail-closed auth (CWE-306).
 *
 * Startup requires a real CONDUIT_S2S_SECRET unless MCP_ALLOW_INSECURE_DEV=1.
 * Known placeholder secrets always refuse to start. The insecure-dev bypass
 * binds 127.0.0.1 only. /mcp rejects a missing or invalid X-Gateway-S2S
 * header. AUTH_MODE=gateway rejects requests that omit vendor credential
 * headers and must not fall back to PETRA_API_KEY in process.env.
 */

import { createHmac } from 'node:crypto';
import type { Server } from 'node:http';
import { connect, type AddressInfo } from 'node:net';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const getCredentialsMock = vi.hoisted(() => vi.fn());
const listTenantsMock = vi.hoisted(() =>
  vi.fn(async () => ({ totalTenants: 1, tenants: [{ petraTenantId: 'T1', name: 'mocked-tenant' }] }))
);

vi.mock('../client.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../client.js')>();
  return {
    ...actual,
    getCredentials: () => {
      const creds = actual.getCredentials();
      getCredentialsMock(creds);
      return creds;
    },
    listTenants: listTenantsMock,
  };
});

import { startHttpServer } from '../http.js';

const S2S_SECRET = 's2s-do-not-log-7f3a';
const ENV_API_KEY = 'env-api-key-must-not-be-used';

const ENV_KEYS = [
  'CONDUIT_S2S_SECRET',
  'MCP_ALLOW_INSECURE_DEV',
  'MCP_HTTP_PORT',
  'MCP_HTTP_HOST',
  'AUTH_MODE',
  'PETRA_API_KEY',
  'LOG_LEVEL',
  'MCP_TRANSPORT',
] as const;

const savedEnv = new Map<string, string | undefined>();
const servers: Server[] = [];

function mintS2sHeader(secret: string, unixSeconds = Math.floor(Date.now() / 1000)): string {
  const message = `t=${unixSeconds}`;
  const hex = createHmac('sha256', secret).update(message).digest('hex');
  return `${message},v1=${hex}`;
}

function captureStderr(): { text: () => string; restore: () => void } {
  const lines: string[] = [];
  const spy = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    lines.push(args.map((arg) => (typeof arg === 'string' ? arg : JSON.stringify(arg))).join(' '));
  });
  return {
    text: () => lines.join('\n'),
    restore: () => spy.mockRestore(),
  };
}

function exitSpy() {
  return vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
    throw new Error(`process.exit:${String(code)}`);
  }) as typeof process.exit);
}

interface HttpResult {
  status: number;
  body: string;
}

function sendHttp(options: {
  port: number;
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: string;
}): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const req = fetch(`http://127.0.0.1:${options.port}${options.path}`, {
      method: options.method,
      headers: options.headers,
      body: options.body,
    }).then(async (res) => {
      resolve({ status: res.status, body: await res.text() });
    }, reject);
    void req;
  });
}

async function listen(): Promise<{ port: number; address: string; server: Server }> {
  const server = await startHttpServer();
  servers.push(server);
  const bound = server.address() as AddressInfo | null;
  if (!bound || typeof bound === 'string') {
    throw new Error('HTTP server did not bind a TCP port');
  }
  return { port: bound.port, address: bound.address, server };
}

async function closeAll(): Promise<void> {
  while (servers.length > 0) {
    const server = servers.pop();
    if (!server) continue;
    await new Promise<void>((resolve, reject) => {
      if (!server.listening) {
        resolve();
        return;
      }
      server.close((err) => (err ? reject(err) : resolve()));
    });
  }
}

function mcpHeaders(extra?: Record<string, string>): Record<string, string> {
  return {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    ...extra,
  };
}

const tenantsCall = JSON.stringify({
  jsonrpc: '2.0',
  id: 1,
  method: 'tools/call',
  params: { name: 'petra_list_tenants', arguments: {} },
});

beforeAll(() => {
  for (const key of ENV_KEYS) savedEnv.set(key, process.env[key]);
});

afterAll(() => {
  for (const key of ENV_KEYS) {
    const value = savedEnv.get(key);
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

beforeEach(() => {
  process.env.MCP_HTTP_PORT = '0';
  process.env.MCP_HTTP_HOST = '127.0.0.1';
  process.env.LOG_LEVEL = 'info';
  delete process.env.CONDUIT_S2S_SECRET;
  delete process.env.MCP_ALLOW_INSECURE_DEV;
  delete process.env.AUTH_MODE;
  delete process.env.PETRA_API_KEY;
  getCredentialsMock.mockReset();
  listTenantsMock.mockClear();
});

afterEach(async () => {
  vi.restoreAllMocks();
  await closeAll();
});

describe('HTTP startup', () => {
  it('refuses to start when CONDUIT_S2S_SECRET is empty', async () => {
    const logs = captureStderr();
    const exit = exitSpy();

    try {
      await expect(startHttpServer()).rejects.toThrow('process.exit:1');
      expect(exit).toHaveBeenCalledWith(1);
      const text = logs.text();
      expect(text).toContain('Refusing to start HTTP server');
      expect(text).toContain('CONDUIT_S2S_SECRET is empty');
      expect(text).toContain('MCP_ALLOW_INSECURE_DEV=1');
      expect(text).not.toContain(S2S_SECRET);
    } finally {
      exit.mockRestore();
      logs.restore();
    }
  });

  it('refuses to start when CONDUIT_S2S_SECRET is whitespace', async () => {
    process.env.CONDUIT_S2S_SECRET = '   ';
    const logs = captureStderr();
    const exit = exitSpy();

    try {
      await expect(startHttpServer()).rejects.toThrow('process.exit:1');
      expect(logs.text()).toContain('CONDUIT_S2S_SECRET is empty');
    } finally {
      exit.mockRestore();
      logs.restore();
    }
  });

  it('still refuses when MCP_ALLOW_INSECURE_DEV is not exactly 1', async () => {
    process.env.MCP_ALLOW_INSECURE_DEV = 'true';
    const logs = captureStderr();
    const exit = exitSpy();

    try {
      await expect(startHttpServer()).rejects.toThrow('process.exit:1');
      expect(logs.text()).toContain('Refusing to start HTTP server');
    } finally {
      exit.mockRestore();
      logs.restore();
    }
  });

  it.each([
    'replace-with-a-real-secret',
    'changeme',
    'change-me',
    'replace-me',
    's2s-secret',
    'your-secret',
    'your-s2s-secret',
  ])('refuses known placeholder %s and does not log it', async (placeholder) => {
    process.env.CONDUIT_S2S_SECRET = placeholder;
    const logs = captureStderr();
    const exit = exitSpy();

    try {
      await expect(startHttpServer()).rejects.toThrow('process.exit:1');
      expect(exit).toHaveBeenCalledWith(1);
      const text = logs.text();
      expect(text).toContain('known placeholder');
      expect(text).toContain('openssl rand -hex 32');
      expect(text).not.toContain(placeholder);
      expect(text).not.toContain(S2S_SECRET);
    } finally {
      exit.mockRestore();
      logs.restore();
    }
  });

  it.each(['secret', 'example', 'placeholder'])(
    'refuses the short placeholder %s without echoing the value',
    async (placeholder) => {
      process.env.CONDUIT_S2S_SECRET = placeholder;
      const logs = captureStderr();
      const exit = exitSpy();

      try {
        await expect(startHttpServer()).rejects.toThrow('process.exit:1');
        const text = logs.text();
        expect(text).toContain('known placeholder');
        expect(text).not.toMatch(new RegExp(`CONDUIT_S2S_SECRET[=:].*${placeholder}`, 'i'));
        expect(text).not.toContain(`"${placeholder}"`);
        expect(text).not.toContain(`'${placeholder}'`);
      } finally {
        exit.mockRestore();
        logs.restore();
      }
    },
  );

  it('refuses a placeholder even when MCP_ALLOW_INSECURE_DEV=1 and does not log it', async () => {
    process.env.CONDUIT_S2S_SECRET = '  Your-S2S-Secret  ';
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    const logs = captureStderr();
    const exit = exitSpy();

    try {
      await expect(startHttpServer()).rejects.toThrow('process.exit:1');
      expect(exit).toHaveBeenCalledWith(1);
      const text = logs.text();
      expect(text).toContain('known placeholder');
      expect(text).not.toContain('Your-S2S-Secret');
      expect(text).not.toContain('your-s2s-secret');
    } finally {
      exit.mockRestore();
      logs.restore();
    }
  });

  it('allows startup with a warning when MCP_ALLOW_INSECURE_DEV=1 and binds 127.0.0.1', async () => {
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    delete process.env.MCP_HTTP_HOST;
    process.env.LOG_LEVEL = 'error';
    const logs = captureStderr();
    const exit = exitSpy();

    try {
      const server = await listen();
      expect(exit).not.toHaveBeenCalled();
      expect(server.address).toBe('127.0.0.1');
      const text = logs.text();
      expect(text).toContain('SECURITY WARNING');
      expect(text).toContain('CONDUIT_S2S_SECRET');
      expect(text).toContain('MCP_ALLOW_INSECURE_DEV=1');
      expect(text).toContain('127.0.0.1');
      expect(text).toContain('DISABLED');
      expect(text).not.toContain(S2S_SECRET);
    } finally {
      exit.mockRestore();
      logs.restore();
    }
  });

  it.each(['localhost', '::1', '[::1]', '127.0.0.2'])(
    'forces 127.0.0.1 when insecure dev host is %s',
    async (host) => {
      process.env.MCP_ALLOW_INSECURE_DEV = '1';
      process.env.MCP_HTTP_HOST = host;
      const logs = captureStderr();
      const exit = exitSpy();

      try {
        const server = await listen();
        expect(exit).not.toHaveBeenCalled();
        expect(server.address).toBe('127.0.0.1');
        expect(logs.text()).toContain('SECURITY WARNING');
      } finally {
        exit.mockRestore();
        logs.restore();
      }
    },
  );

  it.each(['0.0.0.0', '10.1.2.3'])('refuses the dev bypass when MCP_HTTP_HOST is %s', async (host) => {
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    process.env.MCP_HTTP_HOST = host;
    const logs = captureStderr();
    const exit = exitSpy();

    try {
      await expect(startHttpServer()).rejects.toThrow('process.exit:1');
      expect(exit).toHaveBeenCalledWith(1);
      const text = logs.text();
      expect(text).toContain('Refusing to start HTTP server');
      expect(text).toContain('MCP_ALLOW_INSECURE_DEV=1');
      expect(text).toContain('only binds 127.0.0.1');
      expect(text).not.toContain(S2S_SECRET);
    } finally {
      exit.mockRestore();
      logs.restore();
    }
  });

  it('still binds a non-loopback host when CONDUIT_S2S_SECRET is set', async () => {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    process.env.MCP_HTTP_HOST = '0.0.0.0';
    const logs = captureStderr();
    try {
      const server = await listen();
      expect(server.address).toBe('0.0.0.0');
      expect(logs.text()).not.toContain(S2S_SECRET);
      expect(logs.text()).toContain('HTTP streaming server listening on 0.0.0.0:');
    } finally {
      logs.restore();
    }
  });

  it('binds 127.0.0.1 when MCP_HTTP_HOST is unset and a secret is set', async () => {
    delete process.env.MCP_HTTP_HOST;
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    const server = await listen();
    expect(server.address).toBe('127.0.0.1');
  });
});

describe('HTTP /mcp authentication', () => {
  beforeEach(() => {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    process.env.AUTH_MODE = 'gateway';
    process.env.PETRA_API_KEY = ENV_API_KEY;
  });

  it('returns 401 when the S2S header is missing or invalid and does not read credentials', async () => {
    const logs = captureStderr();
    const server = await listen();
    try {
      const missing = await sendHttp({
        port: server.port,
        method: 'POST',
        path: '/mcp',
        headers: mcpHeaders({
          'x-petra-api-key': 'header-key',
        }),
        body: tenantsCall,
      });
      const invalid = await sendHttp({
        port: server.port,
        method: 'POST',
        path: '/mcp',
        headers: mcpHeaders({
          'x-gateway-s2s': mintS2sHeader('wrong-secret'),
          'x-petra-api-key': 'header-key',
        }),
        body: tenantsCall,
      });

      expect(missing.status).toBe(401);
      expect(invalid.status).toBe(401);
      expect(missing.body).toContain('X-Gateway-S2S');
      expect(invalid.body).toContain('X-Gateway-S2S');
      expect(missing.body).not.toContain(S2S_SECRET);
      expect(invalid.body).not.toContain(S2S_SECRET);
      expect(missing.body).not.toContain(ENV_API_KEY);
      expect(logs.text()).not.toContain(S2S_SECRET);
      expect(getCredentialsMock).not.toHaveBeenCalled();
      expect(listTenantsMock).not.toHaveBeenCalled();
    } finally {
      logs.restore();
    }
  });

  it('returns 401 in gateway mode without credential headers and does not use env credentials', async () => {
    const server = await listen();
    const response = await sendHttp({
      port: server.port,
      method: 'POST',
      path: '/mcp',
      headers: mcpHeaders({ 'x-gateway-s2s': mintS2sHeader(S2S_SECRET) }),
      body: tenantsCall,
    });

    expect(response.status).toBe(401);
    expect(response.body).toContain('missing required gateway credential header');
    expect(response.body).toContain('X-Petra-Api-Key');
    expect(response.body).not.toContain(ENV_API_KEY);
    expect(response.body).not.toContain(S2S_SECRET);
    expect(getCredentialsMock).not.toHaveBeenCalled();
    expect(listTenantsMock).not.toHaveBeenCalled();
  });

  it('returns 401 when the credential header is whitespace', async () => {
    const server = await listen();
    const response = await sendHttp({
      port: server.port,
      method: 'POST',
      path: '/mcp',
      headers: mcpHeaders({
        'x-gateway-s2s': mintS2sHeader(S2S_SECRET),
        'x-petra-api-key': '   ',
      }),
      body: tenantsCall,
    });

    expect(response.status).toBe(401);
    expect(getCredentialsMock).not.toHaveBeenCalled();
  });

  it('accepts a valid S2S header plus credential headers and uses those credentials', async () => {
    const logs = captureStderr();
    const server = await listen();
    try {
      const response = await sendHttp({
        port: server.port,
        method: 'POST',
        path: '/mcp',
        headers: mcpHeaders({
          'x-gateway-s2s': mintS2sHeader(S2S_SECRET),
          'x-petra-api-key': 'header-key',
        }),
        body: tenantsCall,
      });

      expect(response.status).toBe(200);
      expect(response.body).not.toContain(S2S_SECRET);
      expect(response.body).not.toContain(ENV_API_KEY);
      expect(response.body).toContain('mocked-tenant');
      expect(listTenantsMock).toHaveBeenCalledWith({ apiKey: 'header-key' });
      const reads = getCredentialsMock.mock.calls.map((call) => call[0]);
      expect(reads).toContainEqual({ apiKey: 'header-key' });
      expect(JSON.stringify(reads)).not.toContain(ENV_API_KEY);
      expect(logs.text()).not.toContain(S2S_SECRET);
    } finally {
      logs.restore();
    }
  });

  it('does not crash on a malformed Host header', async () => {
    const server = await listen();
    const raw = await new Promise<string>((resolve, reject) => {
      const socket = connect(server.port, '127.0.0.1', () => {
        socket.write('GET /health HTTP/1.1\r\nHost: a b\r\nConnection: close\r\n\r\n');
      });
      let data = '';
      socket.on('data', (chunk) => (data += chunk.toString()));
      socket.on('end', () => resolve(data));
      socket.on('error', reject);
    });
    expect(raw.split('\r\n')[0]).toMatch(/^HTTP\/1\.1 (200|400)/);
    const after = await sendHttp({ port: server.port, method: 'GET', path: '/health' });
    expect(after.status).toBe(200);
  });

  it('serves /health and /healthz without authentication and without reading credentials', async () => {
    const server = await listen();
    for (const path of ['/health', '/healthz']) {
      const response = await sendHttp({
        port: server.port,
        method: 'GET',
        path,
      });
      expect(response.status).toBe(200);
      const body = JSON.parse(response.body) as { status?: string; mode?: string; credentials?: unknown };
      expect(body.status).toBe('ok');
      expect(body.mode).toBe('gateway');
      expect(body.credentials).toBeUndefined();
      expect(response.body).not.toContain(S2S_SECRET);
      expect(response.body).not.toContain(ENV_API_KEY);
    }
    expect(getCredentialsMock).not.toHaveBeenCalled();
  });
});

import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash } from 'node:crypto';
import { logger } from './utils/logger.js';
import type {
  PetraBillableUsersResponse,
  PetraCredentials,
  PetraFailedAttacksResponse,
  PetraIncidentsResponse,
  PetraPostureReportsResponse,
  PetraTenantsResponse,
  PetraUsageResponse,
  QueryValue,
} from './types.js';

/**
 * Every Petra public API route lives on this host (docs: API Reference >
 * Introduction). Deliberately not configurable from request headers or tool
 * arguments, so a caller can never point this server at another host.
 */
export const BASE_URL = 'https://api.petrasecurity.com';

/** Petra blocks requests without a User-Agent with 403 (docs: API Troubleshooting). */
export const USER_AGENT = 'wyre-petra-mcp (+https://github.com/WYRE-AI/petra-mcp)';

const REQUEST_TIMEOUT_MS = 30_000;

/**
 * Petra rate-limits every route to 10 requests/minute per route (and the
 * vendor notes we have record 1/minute on /v1/failed-attacks). An agent
 * calling the same read twice in a conversation should not burn that
 * budget, so successful GETs are cached briefly per credential.
 */
const DEFAULT_CACHE_TTL_MS = 60_000;
const ROUTE_CACHE_TTL_MS: Record<string, number> = {
  '/v1/failed-attacks': 5 * 60_000,
};
const MAX_CACHE_ENTRIES = 500;

// Request-scoped credential store. In gateway mode the HTTP layer runs each
// request inside runWithCredentials({apiKey}); getCredentials() reads from
// it. Falls back to process.env for stdio/single-tenant mode.
const credStore = new AsyncLocalStorage<PetraCredentials>();

export function runWithCredentials<T>(creds: PetraCredentials, fn: () => T): T {
  return credStore.run(creds, fn);
}

export function getCredentials(): PetraCredentials | null {
  const scoped = credStore.getStore();
  if (scoped?.apiKey) return scoped;
  const apiKey = process.env.PETRA_API_KEY?.trim();
  if (!apiKey) {
    logger.warn('Missing credentials', { hasApiKey: false });
    return null;
  }
  return { apiKey };
}

/** HTTP 401 - the API key is invalid, missing its Bearer prefix, or was deleted. */
export class PetraAuthError extends Error {}

/** HTTP 403 - the key cannot access this resource (e.g. a tenant outside the key's organization). */
export class PetraForbiddenError extends Error {}

/** HTTP 404 - the tenant was not found in the key's organization. */
export class PetraNotFoundError extends Error {}

/** HTTP 429 - per-route rate limit. retryAfterSeconds comes from Retry-After-public-api. */
export class PetraRateLimitError extends Error {
  constructor(
    message: string,
    readonly retryAfterSeconds?: number
  ) {
    super(message);
  }
}

/** Any other non-2xx or malformed response. */
export class PetraApiError extends Error {
  constructor(
    message: string,
    readonly status?: number
  ) {
    super(message);
  }
}

interface CacheEntry {
  expiresAt: number;
  value: unknown;
}

const responseCache = new Map<string, CacheEntry>();
const inFlight = new Map<string, Promise<unknown>>();

/** Clears the response cache. Exported for tests. */
export function clearResponseCache(): void {
  responseCache.clear();
  inFlight.clear();
}

/**
 * Cache keys use a SHA-256 of the API key, never the key itself, so two
 * tenants sharing one gateway process can never read each other's cached
 * responses and no raw credential sits in a long-lived map.
 */
function cacheKey(creds: PetraCredentials, url: string): string {
  const keyHash = createHash('sha256').update(creds.apiKey).digest('hex');
  return `${keyHash}|${url}`;
}

function buildUrl(path: string, query?: Record<string, QueryValue>): string {
  const url = new URL(path, BASE_URL);
  if (query) {
    // Sorted so the same options in a different key order share one cache entry.
    for (const [key, value] of Object.entries(query).sort(([a], [b]) => a.localeCompare(b))) {
      if (value === undefined || value === '') continue;
      url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

async function errorDetail(res: Response): Promise<string> {
  try {
    const text = (await res.text()).trim();
    if (!text) return '';
    try {
      const parsed = JSON.parse(text) as { error?: unknown; message?: unknown };
      const msg = parsed.message ?? parsed.error;
      if (typeof msg === 'string' && msg) return `: ${msg.slice(0, 300)}`;
    } catch {
      // not JSON, fall through
    }
    return `: ${text.slice(0, 300)}`;
  } catch {
    return '';
  }
}

async function fetchJson<T>(creds: PetraCredentials, url: string): Promise<T> {
  const route = new URL(url).pathname;
  let res: Response;
  try {
    res = await fetch(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${creds.apiKey}`,
        Accept: 'application/json',
        'User-Agent': USER_AGENT,
      },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (err) {
    const name = (err as Error).name;
    if (name === 'TimeoutError' || name === 'AbortError') {
      throw new PetraApiError(`Petra API request to ${route} timed out after ${REQUEST_TIMEOUT_MS / 1000}s`);
    }
    throw new PetraApiError(`Could not reach the Petra API (${route}): ${(err as Error).message}`);
  }

  if (!res.ok) {
    const detail = await errorDetail(res);
    if (res.status === 401) {
      throw new PetraAuthError(
        `Petra rejected the API key (HTTP 401${detail}). Check the key still exists under Settings > API Keys in the Petra portal.`
      );
    }
    if (res.status === 403) {
      throw new PetraForbiddenError(`Petra denied access to ${route} (HTTP 403${detail}).`);
    }
    if (res.status === 404) {
      throw new PetraNotFoundError(
        `Petra returned 404 for ${route}${detail}. The tenant ID may not belong to this organization; use petra_list_tenants to find valid IDs.`
      );
    }
    if (res.status === 429) {
      const raw = res.headers.get('retry-after-public-api') ?? res.headers.get('retry-after');
      const seconds = raw !== null && /^\d+$/.test(raw.trim()) ? Number(raw.trim()) : undefined;
      throw new PetraRateLimitError(
        `Petra rate limit hit on ${route} (HTTP 429). ` +
          (seconds !== undefined ? `Retry in ${seconds}s.` : 'Wait a minute before retrying.') +
          ' Petra allows about 10 requests per minute per route.',
        seconds
      );
    }
    throw new PetraApiError(`Petra API error on ${route} (HTTP ${res.status}${detail})`, res.status);
  }

  try {
    return (await res.json()) as T;
  } catch {
    throw new PetraApiError(`Petra returned a non-JSON response for ${route}`, res.status);
  }
}

/** Cached, de-duplicated GET. Only successful responses are cached. */
export async function petraGet<T>(
  creds: PetraCredentials,
  path: string,
  query?: Record<string, QueryValue>
): Promise<T> {
  const url = buildUrl(path, query);
  const key = cacheKey(creds, url);
  const now = Date.now();

  const hit = responseCache.get(key);
  if (hit && hit.expiresAt > now) return hit.value as T;
  if (hit) responseCache.delete(key);

  const pending = inFlight.get(key);
  if (pending) return pending as Promise<T>;

  const promise = fetchJson<T>(creds, url)
    .then((value) => {
      const ttl = ROUTE_CACHE_TTL_MS[path] ?? DEFAULT_CACHE_TTL_MS;
      if (responseCache.size >= MAX_CACHE_ENTRIES) {
        const oldest = responseCache.keys().next().value;
        if (oldest !== undefined) responseCache.delete(oldest);
      }
      responseCache.set(key, { expiresAt: Date.now() + ttl, value });
      return value;
    })
    .finally(() => {
      inFlight.delete(key);
    });
  inFlight.set(key, promise);
  return promise;
}

export function listTenants(creds: PetraCredentials): Promise<PetraTenantsResponse> {
  return petraGet<PetraTenantsResponse>(creds, '/v1/tenants');
}

export function listIncidents(
  creds: PetraCredentials,
  opts: { tenantId?: string; startDate?: string; limit?: number } = {}
): Promise<PetraIncidentsResponse> {
  return petraGet<PetraIncidentsResponse>(creds, '/v1/incidents', opts);
}

export function getFailedAttacks(
  creds: PetraCredentials,
  opts: { tenantId: string; startDate?: string; endDate?: string }
): Promise<PetraFailedAttacksResponse> {
  return petraGet<PetraFailedAttacksResponse>(creds, '/v1/failed-attacks', opts);
}

export function getUsage(creds: PetraCredentials, opts: { asOf?: string } = {}): Promise<PetraUsageResponse> {
  return petraGet<PetraUsageResponse>(creds, '/v1/usage', opts);
}

export function listBillableUsers(
  creds: PetraCredentials,
  opts: { tenantId: string }
): Promise<PetraBillableUsersResponse> {
  return petraGet<PetraBillableUsersResponse>(creds, '/v1/billable-users', opts);
}

export function listPostureReports(
  creds: PetraCredentials,
  opts: { tenantId?: string; latestOnly?: boolean; startDate?: string; limit?: number } = {}
): Promise<PetraPostureReportsResponse> {
  return petraGet<PetraPostureReportsResponse>(creds, '/v1/posture-reports', opts);
}

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  BASE_URL,
  PetraApiError,
  PetraAuthError,
  PetraNotFoundError,
  PetraRateLimitError,
  USER_AGENT,
  clearResponseCache,
  getCredentials,
  listIncidents,
  listTenants,
  petraGet,
  runWithCredentials,
} from '../client.js';
import { TENANTS } from './fixtures.js';

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
}

const CREDS = { apiKey: 'petra_test_key' };

describe('client', () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
    clearResponseCache();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.PETRA_API_KEY;
  });

  it('sends Bearer auth, Accept and a User-Agent to api.petrasecurity.com', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(TENANTS));
    await listTenants(CREDS);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(`${BASE_URL}/v1/tenants`);
    expect(init.method).toBe('GET');
    expect(init.headers.Authorization).toBe('Bearer petra_test_key');
    expect(init.headers['User-Agent']).toBe(USER_AGENT);
    expect(init.headers.Accept).toBe('application/json');
  });

  it('drops undefined and empty query params and encodes the rest', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ incidents: [] }));
    await listIncidents(CREDS, { tenantId: 'ZZk90t', startDate: undefined, limit: 50 });
    const parsed = new URL(fetchMock.mock.calls[0][0] as string);
    expect(parsed.pathname).toBe('/v1/incidents');
    expect(parsed.searchParams.get('tenantId')).toBe('ZZk90t');
    expect(parsed.searchParams.get('limit')).toBe('50');
    expect(parsed.searchParams.has('startDate')).toBe(false);
  });

  it('caches successful responses per API key and per URL', async () => {
    fetchMock.mockImplementation(async () => jsonResponse(TENANTS));
    await listTenants(CREDS);
    await listTenants(CREDS);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await listTenants({ apiKey: 'other-tenant-key' });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('de-duplicates concurrent identical requests', async () => {
    fetchMock.mockImplementation(async () => jsonResponse(TENANTS));
    await Promise.all([listTenants(CREDS), listTenants(CREDS), listTenants(CREDS)]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('does not cache failures', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ error: 'boom' }, 500)).mockResolvedValueOnce(jsonResponse(TENANTS));
    await expect(listTenants(CREDS)).rejects.toBeInstanceOf(PetraApiError);
    await expect(listTenants(CREDS)).resolves.toEqual(TENANTS);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('expires cached entries after the TTL', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    try {
      fetchMock.mockImplementation(async () => jsonResponse(TENANTS));
      await listTenants(CREDS);
      vi.setSystemTime(Date.now() + 61_000);
      await listTenants(CREDS);
      expect(fetchMock).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('maps 401 to PetraAuthError without echoing the key', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ error: 'Invalid API key' }, 401));
    const err = (await listTenants(CREDS).catch((e: unknown) => e)) as Error;
    expect(err).toBeInstanceOf(PetraAuthError);
    expect(err.message).toContain('HTTP 401');
    expect(err.message).not.toContain('petra_test_key');
  });

  it('maps 404 to PetraNotFoundError with a hint', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ error: 'Tenant not found' }, 404));
    const err = (await petraGet(CREDS, '/v1/incidents', { tenantId: 'nope' }).catch((e: unknown) => e)) as Error;
    expect(err).toBeInstanceOf(PetraNotFoundError);
    expect(err.message).toContain('petra_list_tenants');
  });

  it('maps 429 to PetraRateLimitError using Retry-After-public-api', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ error: 'Too many' }, 429, { 'Retry-After-public-api': '42' }));
    const err = (await listTenants(CREDS).catch((e: unknown) => e)) as PetraRateLimitError;
    expect(err).toBeInstanceOf(PetraRateLimitError);
    expect(err.retryAfterSeconds).toBe(42);
    expect(err.message).toContain('Retry in 42s');
  });

  it('reports network failures and timeouts as PetraApiError', async () => {
    fetchMock.mockRejectedValueOnce(Object.assign(new Error('aborted'), { name: 'TimeoutError' }));
    await expect(listTenants(CREDS)).rejects.toThrow(/timed out/);
    fetchMock.mockRejectedValueOnce(new Error('ECONNREFUSED'));
    await expect(listTenants(CREDS)).rejects.toThrow(/Could not reach the Petra API/);
  });

  it('reports a non-JSON 200 as PetraApiError', async () => {
    fetchMock.mockResolvedValueOnce(new Response('<html>', { status: 200 }));
    await expect(listTenants(CREDS)).rejects.toThrow(/non-JSON/);
  });

  it('prefers request-scoped credentials over PETRA_API_KEY', () => {
    process.env.PETRA_API_KEY = 'env-key';
    expect(getCredentials()).toEqual({ apiKey: 'env-key' });
    runWithCredentials({ apiKey: 'scoped-key' }, () => {
      expect(getCredentials()).toEqual({ apiKey: 'scoped-key' });
    });
  });

  it('returns null when no key is configured', () => {
    expect(getCredentials()).toBeNull();
  });
});

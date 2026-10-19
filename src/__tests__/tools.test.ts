import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { clearResponseCache } from '../client.js';
import { ALL_TOOLS, dispatchToolCall } from '../tools/index.js';
import { BILLABLE_USERS, FAILED_ATTACKS, INCIDENTS, POSTURE, TENANTS, USAGE } from './fixtures.js';
import { textOf } from './test-helpers.js';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

function calledUrl(fetchMock: ReturnType<typeof vi.fn>, index = 0): URL {
  return new URL(fetchMock.mock.calls[index][0] as string);
}

async function call(name: string, args: Record<string, unknown> = {}) {
  const result = await dispatchToolCall(name, args);
  return { result, text: textOf(result) };
}

describe('tool surface', () => {
  it('exposes the StackJack parity five plus incident lookup and posture reports', () => {
    expect(ALL_TOOLS.map((t) => t.name).sort()).toEqual([
      'petra_get_failed_attacks',
      'petra_get_incident',
      'petra_get_usage',
      'petra_list_billable_users',
      'petra_list_incidents',
      'petra_list_posture_reports',
      'petra_list_tenants',
    ]);
  });

  it('marks every tool read-only and non-destructive', () => {
    for (const tool of ALL_TOOLS) {
      expect(tool.name.startsWith('petra_')).toBe(true);
      expect(tool.annotations?.readOnlyHint).toBe(true);
      expect(tool.annotations?.destructiveHint).toBe(false);
      expect(tool.inputSchema.type).toBe('object');
    }
  });

  it('returns an error for unknown tools', async () => {
    const result = await dispatchToolCall('petra_delete_everything', {});
    expect(result.isError).toBe(true);
  });
});

describe('tool handlers', () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
    clearResponseCache();
    process.env.PETRA_API_KEY = 'petra_test_key';
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.PETRA_API_KEY;
  });

  it('errors clearly without an API key', async () => {
    delete process.env.PETRA_API_KEY;
    const { result, text } = await call('petra_list_tenants');
    expect(result.isError).toBe(true);
    expect(text).toContain('PETRA_API_KEY');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  describe('petra_list_tenants', () => {
    it('calls GET /v1/tenants and returns all tenants by default', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse(TENANTS));
      const { text } = await call('petra_list_tenants');
      const body = JSON.parse(text);
      expect(calledUrl(fetchMock).pathname).toBe('/v1/tenants');
      expect(body.returned).toBe(2);
      expect(body.pausedReturned).toBe(1);
    });

    it('filters paused tenants and by name locally', async () => {
      fetchMock.mockResolvedValue(jsonResponse(TENANTS));
      const paused = JSON.parse((await call('petra_list_tenants', { includePaused: false })).text);
      expect(paused.tenants.map((t: { petraTenantId: string }) => t.petraTenantId)).toEqual(['ZZk90t']);
      const named = JSON.parse((await call('petra_list_tenants', { nameContains: 'GLOBEX' })).text);
      expect(named.tenants.map((t: { petraTenantId: string }) => t.petraTenantId)).toEqual(['Y3mPqr']);
    });
  });

  describe('petra_list_incidents', () => {
    it('passes tenantId, startDate and limit to GET /v1/incidents', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse(INCIDENTS));
      const { text } = await call('petra_list_incidents', { tenantId: 'ZZk90t', startDate: '2026-01-01', limit: 2 });
      const url = calledUrl(fetchMock);
      expect(url.pathname).toBe('/v1/incidents');
      expect(url.searchParams.get('tenantId')).toBe('ZZk90t');
      expect(url.searchParams.get('startDate')).toBe('2026-01-01');
      expect(url.searchParams.get('limit')).toBe('2');
      const body = JSON.parse(text);
      expect(body.returned).toBe(2);
      expect(body.liveCount).toBe(1);
      expect(body.limitReached).toBe(true);
    });

    it('omits tenantId when not given (all tenants)', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse(INCIDENTS));
      await call('petra_list_incidents');
      expect(calledUrl(fetchMock).searchParams.has('tenantId')).toBe(false);
    });

    it('applies local filters and can drop the phishing email block', async () => {
      fetchMock.mockResolvedValue(jsonResponse(INCIDENTS));
      const live = JSON.parse((await call('petra_list_incidents', { liveOnly: true })).text);
      expect(live.incidents).toHaveLength(1);
      expect(live.incidents[0].isLive).toBe(true);
      const status = JSON.parse((await call('petra_list_incidents', { remediationStatus: 'remediated_prior_to_onboarding' })).text);
      expect(status.incidents.map((i: { id: string }) => i.id)).toEqual(['0776897d-be9d-4785-82b1-e240e64f2476']);
      const user = JSON.parse((await call('petra_list_incidents', { userPrincipalName: 'ASHA.STREICH@acmecorp.com' })).text);
      expect(user.returned).toBe(1);
      const compact = JSON.parse((await call('petra_list_incidents', { includePhishingEmail: false })).text);
      expect(compact.incidents[0].phishingEmail).toBeUndefined();
    });

    it('rejects bad arguments before calling Petra', async () => {
      for (const args of [{ limit: 0 }, { limit: 501 }, { limit: 2.5 }, { startDate: 'last week' }, { tenantId: '../admin' }]) {
        const { result } = await call('petra_list_incidents', args);
        expect(result.isError).toBe(true);
      }
      expect(fetchMock).not.toHaveBeenCalled();
    });
  });

  describe('petra_get_incident', () => {
    it('finds an incident by id from the newest 500', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse(INCIDENTS));
      const { text } = await call('petra_get_incident', { incidentId: '0776897D-be9d-4785-82b1-e240e64f2476' });
      expect(JSON.parse(text).user.displayName).toBe('Fleta Rowe');
      expect(calledUrl(fetchMock).searchParams.get('limit')).toBe('500');
    });

    it('errors when the incident is not found or id is missing', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse(INCIDENTS));
      const missing = await call('petra_get_incident', { incidentId: '00000000-0000-0000-0000-000000000000' });
      expect(missing.result.isError).toBe(true);
      expect(missing.text).toContain('not found');
      const noId = await call('petra_get_incident', {});
      expect(noId.result.isError).toBe(true);
    });
  });

  describe('petra_get_failed_attacks', () => {
    it('requires tenantId', async () => {
      const { result, text } = await call('petra_get_failed_attacks');
      expect(result.isError).toBe(true);
      expect(text).toContain('tenantId is required');
    });

    it('calls GET /v1/failed-attacks with the window', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse(FAILED_ATTACKS));
      const { text } = await call('petra_get_failed_attacks', {
        tenantId: 'a1b2c3d4-5e6f-7890-abcd-ef1234567890',
        startDate: '2025-01-05',
        endDate: '2025-02-25T00:00:00Z',
      });
      const url = calledUrl(fetchMock);
      expect(url.pathname).toBe('/v1/failed-attacks');
      expect(url.searchParams.get('tenantId')).toBe('a1b2c3d4-5e6f-7890-abcd-ef1234567890');
      expect(url.searchParams.get('endDate')).toBe('2025-02-25T00:00:00Z');
      expect(JSON.parse(text).totalCount).toBe(50471);
    });

    it('rejects startDate after endDate', async () => {
      const { result } = await call('petra_get_failed_attacks', { tenantId: 'ZZk90t', startDate: '2026-02-01', endDate: '2026-01-01' });
      expect(result.isError).toBe(true);
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('surfaces rate limiting as a tool error', async () => {
      fetchMock.mockResolvedValueOnce(
        new Response('{"error":"rate"}', { status: 429, headers: { 'Retry-After-public-api': '55' } })
      );
      const { result, text } = await call('petra_get_failed_attacks', { tenantId: 'ZZk90t' });
      expect(result.isError).toBe(true);
      expect(text).toContain('Retry in 55s');
    });
  });

  describe('petra_get_usage', () => {
    it('calls GET /v1/usage with asOf and totals the rows', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse(USAGE));
      const { text } = await call('petra_get_usage', { asOf: '2026-03-01' });
      expect(calledUrl(fetchMock).pathname).toBe('/v1/usage');
      expect(calledUrl(fetchMock).searchParams.get('asOf')).toBe('2026-03-01');
      const body = JSON.parse(text);
      expect(body.summary).toEqual({ tenantsReturned: 3, totalLicensedUsers: 65, billableUsersThisMonth: 58 });
      expect(body.organizationName).toBe('Example MSP');
    });

    it('can exclude paused tenants and filter by billable status', async () => {
      fetchMock.mockResolvedValue(jsonResponse(USAGE));
      const active = JSON.parse((await call('petra_get_usage', { includePaused: false, billableStatus: 'Active' })).text);
      expect(active.summary).toEqual({ tenantsReturned: 1, totalLicensedUsers: 40, billableUsersThisMonth: 38 });
    });

    it('validates asOf and billableStatus', async () => {
      expect((await call('petra_get_usage', { asOf: '03/01/2026' })).result.isError).toBe(true);
      expect((await call('petra_get_usage', { billableStatus: 'Gold' })).result.isError).toBe(true);
      expect(fetchMock).not.toHaveBeenCalled();
    });
  });

  describe('petra_list_billable_users', () => {
    it('calls GET /v1/billable-users with a Petra tenant ID', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse(BILLABLE_USERS));
      const { text } = await call('petra_list_billable_users', { tenantId: 'ZZk90t' });
      expect(calledUrl(fetchMock).pathname).toBe('/v1/billable-users');
      expect(calledUrl(fetchMock).searchParams.get('tenantId')).toBe('ZZk90t');
      expect(JSON.parse(text).returned).toBe(2);
    });

    it('resolves a Microsoft tenant ID through /v1/tenants first', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse(TENANTS)).mockResolvedValueOnce(jsonResponse(BILLABLE_USERS));
      await call('petra_list_billable_users', { tenantId: 'A1B2C3D4-5E6F-7890-ABCD-EF1234567890' });
      expect(calledUrl(fetchMock, 0).pathname).toBe('/v1/tenants');
      expect(calledUrl(fetchMock, 1).searchParams.get('tenantId')).toBe('ZZk90t');
    });

    it('errors for an unknown Microsoft tenant ID', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse(TENANTS));
      const { result, text } = await call('petra_list_billable_users', { tenantId: '99999999-9999-9999-9999-999999999999' });
      expect(result.isError).toBe(true);
      expect(text).toContain('No Petra tenant');
    });

    it('can return enabled users only', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse(BILLABLE_USERS));
      const body = JSON.parse((await call('petra_list_billable_users', { tenantId: 'ZZk90t', enabledOnly: true })).text);
      expect(body.returned).toBe(1);
      expect(body.totalBillableUsers).toBe(2);
    });
  });

  describe('petra_list_posture_reports', () => {
    it('passes filters to GET /v1/posture-reports', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse(POSTURE));
      await call('petra_list_posture_reports', { tenantId: 'ZZk90t', latestOnly: false, limit: 10 });
      const url = calledUrl(fetchMock);
      expect(url.pathname).toBe('/v1/posture-reports');
      expect(url.searchParams.get('latestOnly')).toBe('false');
      expect(url.searchParams.get('limit')).toBe('10');
    });

    it('can drop the per-control checks', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse(POSTURE));
      const body = JSON.parse((await call('petra_list_posture_reports', { includeChecks: false })).text);
      expect(body.reports[0].checks).toBeUndefined();
      expect(body.reports[0].score).toBe(81);
    });
  });
});

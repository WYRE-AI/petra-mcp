import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getCredentials, getUsage, listBillableUsers, listTenants } from '../client.js';
import type { PetraCredentials, PetraTenantUsage } from '../types.js';
import type { CallToolResult } from './types.js';
import {
  ArgumentError,
  READ_ONLY_ANNOTATIONS,
  TENANT_ID_DESCRIPTION,
  boolArg,
  dateArg,
  errorResult,
  optionalString,
  requireCredentials,
  tenantIdArg,
  textResult,
} from './shared.js';

const BILLABLE_STATUSES = ['Trial', 'Active', 'NFR', 'Deleted'] as const;
const MICROSOFT_TENANT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const TENANT_TOOLS: Tool[] = [
  {
    name: 'petra_list_tenants',
    description:
      'List every client tenant (Microsoft 365 customer) in the Petra organization, alphabetically, with its Petra tenant ID, Microsoft tenant ID, onboarding date and paused flag. Start here to find the tenantId other petra_* tools take. Removed tenants are excluded; paused tenants are included unless includePaused is false.',
    annotations: { ...READ_ONLY_ANNOTATIONS, title: 'List Petra tenants' },
    inputSchema: {
      type: 'object',
      properties: {
        nameContains: {
          type: 'string',
          description: 'Case-insensitive substring match on the tenant name (filtered locally; Petra has no search parameter).',
        },
        includePaused: {
          type: 'boolean',
          description: 'Include tenants whose ingestion is paused. Defaults to true.',
        },
      },
    },
  },
  {
    name: 'petra_get_usage',
    description:
      'Get the whole-organization Petra billing snapshot in one call: for every tenant, the service (Monitoring or Autopsy), billableStatus (Trial, Active, NFR, Deleted), totalLicensedUsers, billableUsersThisMonth, proratingPercentageThisMonth and firstBillableDate, plus totals across the returned tenants. Use for invoice reconciliation against the PSA.',
    annotations: { ...READ_ONLY_ANNOTATIONS, title: 'Get Petra usage and billing' },
    inputSchema: {
      type: 'object',
      properties: {
        asOf: { type: 'string', description: 'Usage as of this date (YYYY-MM-DD). Defaults to today.' },
        includePaused: {
          type: 'boolean',
          description: 'Include paused tenants. Defaults to true. Set false so paused tenants do not inflate counts.',
        },
        billableStatus: {
          type: 'string',
          enum: [...BILLABLE_STATUSES],
          description: 'Only return tenants with this billable status (filtered locally).',
        },
      },
    },
  },
  {
    name: 'petra_list_billable_users',
    description:
      'List the individual billable users for ONE tenant (users with an assigned Microsoft license that are not deleted), with display name, UPN, mail, enabled flag and license SKU IDs, plus totalBillableUsers and projectedBillableUnitsThisMonth. This is the user-level detail behind petra_get_usage. A Microsoft tenant ID is resolved to the Petra tenant ID automatically.',
    annotations: { ...READ_ONLY_ANNOTATIONS, title: 'List Petra billable users' },
    inputSchema: {
      type: 'object',
      properties: {
        tenantId: { type: 'string', description: TENANT_ID_DESCRIPTION },
        enabledOnly: {
          type: 'boolean',
          description: 'Only return users whose account is enabled (filtered locally). Totals still reflect Petra’s count.',
        },
      },
      required: ['tenantId'],
    },
  },
];

/**
 * /v1/billable-users documents only the Petra tenant ID. The other routes
 * accept a Microsoft tenant ID too, so resolve a GUID through /v1/tenants to
 * keep the tools consistent.
 */
async function resolvePetraTenantId(creds: PetraCredentials, tenantId: string): Promise<string> {
  if (!MICROSOFT_TENANT_ID_RE.test(tenantId)) return tenantId;
  const { tenants = [] } = await listTenants(creds);
  const match = tenants.find((t) => t.microsoftTenantId?.toLowerCase() === tenantId.toLowerCase());
  if (!match?.petraTenantId) {
    throw new ArgumentError(`No Petra tenant has Microsoft tenant ID ${tenantId}. Use petra_list_tenants to find it.`);
  }
  return match.petraTenantId;
}

function sum(rows: PetraTenantUsage[], key: 'totalLicensedUsers' | 'billableUsersThisMonth'): number {
  return rows.reduce((acc, row) => acc + (typeof row[key] === 'number' ? (row[key] as number) : 0), 0);
}

export async function handleTenantTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'petra_list_tenants') {
      const nameContains = optionalString(args, 'nameContains')?.toLowerCase();
      const includePaused = boolArg(args, 'includePaused') ?? true;
      const response = await listTenants(creds!);
      const all = response.tenants ?? [];
      const tenants = all.filter(
        (t) => (includePaused || !t.isPaused) && (!nameContains || (t.name ?? '').toLowerCase().includes(nameContains))
      );
      return textResult({
        totalTenants: response.totalTenants ?? all.length,
        returned: tenants.length,
        pausedReturned: tenants.filter((t) => t.isPaused).length,
        tenants,
      });
    }

    if (name === 'petra_get_usage') {
      const asOf = dateArg(args, 'asOf');
      const includePaused = boolArg(args, 'includePaused') ?? true;
      const billableStatus = optionalString(args, 'billableStatus');
      if (billableStatus && !(BILLABLE_STATUSES as readonly string[]).includes(billableStatus)) {
        throw new ArgumentError(`billableStatus must be one of ${BILLABLE_STATUSES.join(', ')}.`);
      }
      const response = await getUsage(creds!, { asOf });
      const tenants = (response.tenants ?? []).filter(
        (t) => (includePaused || !t.isPaused) && (!billableStatus || t.billableStatus === billableStatus)
      );
      return textResult({
        ...response,
        tenants,
        summary: {
          tenantsReturned: tenants.length,
          totalLicensedUsers: sum(tenants, 'totalLicensedUsers'),
          billableUsersThisMonth: sum(tenants, 'billableUsersThisMonth'),
        },
      });
    }

    if (name === 'petra_list_billable_users') {
      const tenantId = await resolvePetraTenantId(creds!, tenantIdArg(args, true));
      const enabledOnly = boolArg(args, 'enabledOnly') ?? false;
      const response = await listBillableUsers(creds!, { tenantId });
      const users = response.users ?? [];
      const filtered = enabledOnly ? users.filter((u) => u.accountEnabled === true) : users;
      return textResult({ ...response, returned: filtered.length, users: filtered });
    }

    return errorResult(`Unknown tenant tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}

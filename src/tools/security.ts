import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getCredentials, getFailedAttacks, listIncidents, listPostureReports } from '../client.js';
import type { PetraIncident } from '../types.js';
import type { CallToolResult } from './types.js';
import {
  ArgumentError,
  READ_ONLY_ANNOTATIONS,
  TENANT_ID_DESCRIPTION,
  boolArg,
  dateTimeArg,
  errorResult,
  intArg,
  optionalString,
  requireCredentials,
  tenantIdArg,
  textResult,
} from './shared.js';

const INCIDENT_ID_RE = /^[A-Za-z0-9-]{1,128}$/;
const MAX_LIMIT = 500;

export const SECURITY_TOOLS: Tool[] = [
  {
    name: 'petra_list_incidents',
    description:
      'List Microsoft 365 identity-compromise incidents Petra detected (account takeovers, BEC), newest first: compromised user, occurred/created time, remediation status, whether the attacker is still live, dwell time, and the phishing email that led to it. Omit tenantId to search every tenant in the organization. Petra only alerts on real compromises.',
    annotations: { ...READ_ONLY_ANNOTATIONS, title: 'List Petra incidents' },
    inputSchema: {
      type: 'object',
      properties: {
        tenantId: { type: 'string', description: `Limit to one tenant. ${TENANT_ID_DESCRIPTION}` },
        startDate: {
          type: 'string',
          description: 'Only incidents created on or after this ISO 8601 date or date-time (e.g. 2026-03-01).',
        },
        limit: {
          type: 'integer',
          minimum: 1,
          maximum: MAX_LIMIT,
          description: 'Maximum incidents Petra returns (1-500, default 100). Local filters below apply after this limit.',
        },
        remediationStatus: {
          type: 'string',
          description: 'Only incidents with this remediationStatus (e.g. REMEDIATED, REMEDIATED_PRIOR_TO_ONBOARDING). Filtered locally, case-insensitive.',
        },
        liveOnly: { type: 'boolean', description: 'Only incidents where the attacker is still live (isLive=true).' },
        userPrincipalName: {
          type: 'string',
          description: 'Only incidents for this user (UPN or mail, case-insensitive). Filtered locally.',
        },
        includePhishingEmail: {
          type: 'boolean',
          description: 'Include the phishingEmail details block. Defaults to true; set false for a compact list.',
        },
      },
    },
  },
  {
    name: 'petra_get_incident',
    description:
      'Get one Petra incident by its ID, with full user and phishing-email detail. Petra has no single-incident route, so this searches the newest 500 incidents (narrow with tenantId or startDate for older ones).',
    annotations: { ...READ_ONLY_ANNOTATIONS, title: 'Get Petra incident' },
    inputSchema: {
      type: 'object',
      properties: {
        incidentId: { type: 'string', description: 'Incident ID (UUID) from petra_list_incidents or the Petra incident URL.' },
        tenantId: { type: 'string', description: `Tenant the incident belongs to, to widen the search window. ${TENANT_ID_DESCRIPTION}` },
        startDate: { type: 'string', description: 'Only search incidents created on or after this ISO 8601 date.' },
      },
      required: ['incidentId'],
    },
  },
  {
    name: 'petra_get_failed_attacks',
    description:
      'Get the BLOCKED (failed) attack summary for one tenant: total count, counts by origin country, a daily breakdown by attack type (e.g. PASSWORD_SPRAY, LEGACY_AUTH), and the most-targeted users with the countries their attackers came from. Defaults to the last 30 days. Petra rate-limits this route heavily, so results are cached for 5 minutes.',
    annotations: { ...READ_ONLY_ANNOTATIONS, title: 'Get Petra failed attacks' },
    inputSchema: {
      type: 'object',
      properties: {
        tenantId: { type: 'string', description: TENANT_ID_DESCRIPTION },
        startDate: {
          type: 'string',
          description: 'Start of the window, ISO 8601 date or date-time. Defaults to 30 days before endDate.',
        },
        endDate: { type: 'string', description: 'End of the window, ISO 8601 date or date-time. Defaults to now.' },
      },
      required: ['tenantId'],
    },
  },
  {
    name: 'petra_list_posture_reports',
    description:
      'Get completed Microsoft 365 security posture reports: score and grade (with previous score/grade on follow-ups), control rollup (secure, fixed, open, drifted), the Global Administrators review (count, MFA strength, password age), top risks, and every check with its status, severity, current state and suggested fix. By default returns the latest report per tenant.',
    annotations: { ...READ_ONLY_ANNOTATIONS, title: 'List Petra posture reports' },
    inputSchema: {
      type: 'object',
      properties: {
        tenantId: { type: 'string', description: `Limit to one tenant. ${TENANT_ID_DESCRIPTION}` },
        latestOnly: {
          type: 'boolean',
          description: 'Only the most recent completed report per tenant (default true). Set false for history, newest first.',
        },
        startDate: { type: 'string', description: 'Only reports completed on or after this ISO 8601 date or date-time.' },
        limit: { type: 'integer', minimum: 1, maximum: MAX_LIMIT, description: 'Maximum reports (1-500, default 100).' },
        includeChecks: {
          type: 'boolean',
          description: 'Include the per-control checks array. Defaults to true; set false for a compact score/top-risks view.',
        },
      },
    },
  },
];

function matchesUser(incident: PetraIncident, upn: string): boolean {
  const u = incident.user;
  return [u?.userPrincipalName, u?.mail].some((v) => typeof v === 'string' && v.toLowerCase() === upn);
}

export async function handleSecurityTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'petra_list_incidents') {
      const tenantId = tenantIdArg(args);
      const startDate = dateTimeArg(args, 'startDate');
      const limit = intArg(args, 'limit', 1, MAX_LIMIT);
      const remediationStatus = optionalString(args, 'remediationStatus')?.toUpperCase();
      const liveOnly = boolArg(args, 'liveOnly') ?? false;
      const upn = optionalString(args, 'userPrincipalName')?.toLowerCase();
      const includePhishingEmail = boolArg(args, 'includePhishingEmail') ?? true;

      const response = await listIncidents(creds!, { tenantId, startDate, limit });
      const fetched = response.incidents ?? [];
      const incidents = fetched
        .filter((i) => !remediationStatus || (i.remediationStatus ?? '').toUpperCase() === remediationStatus)
        .filter((i) => !liveOnly || i.isLive === true)
        .filter((i) => !upn || matchesUser(i, upn))
        .map((i) => {
          if (includePhishingEmail) return i;
          const { phishingEmail: _omitted, ...rest } = i;
          return rest;
        });
      return textResult({
        fetched: fetched.length,
        returned: incidents.length,
        liveCount: incidents.filter((i) => i.isLive === true).length,
        limitReached: fetched.length >= (limit ?? 100),
        incidents,
      });
    }

    if (name === 'petra_get_incident') {
      const incidentId = optionalString(args, 'incidentId');
      if (!incidentId) throw new ArgumentError('incidentId is required.');
      if (!INCIDENT_ID_RE.test(incidentId)) throw new ArgumentError('incidentId must be a Petra incident ID (UUID).');
      const tenantId = tenantIdArg(args);
      const startDate = dateTimeArg(args, 'startDate');
      const response = await listIncidents(creds!, { tenantId, startDate, limit: MAX_LIMIT });
      const incident = (response.incidents ?? []).find((i) => i.id?.toLowerCase() === incidentId.toLowerCase());
      if (!incident) {
        return errorResult(
          `Incident ${incidentId} was not found in the newest ${MAX_LIMIT} incidents` +
            (tenantId ? ` for tenant ${tenantId}` : '') +
            '. Pass tenantId (and startDate) to narrow the search.'
        );
      }
      return textResult(incident);
    }

    if (name === 'petra_get_failed_attacks') {
      const tenantId = tenantIdArg(args, true);
      const startDate = dateTimeArg(args, 'startDate');
      const endDate = dateTimeArg(args, 'endDate');
      if (startDate && endDate && Date.parse(startDate) > Date.parse(endDate)) {
        throw new ArgumentError('startDate must be on or before endDate.');
      }
      return textResult(await getFailedAttacks(creds!, { tenantId, startDate, endDate }));
    }

    if (name === 'petra_list_posture_reports') {
      const tenantId = tenantIdArg(args);
      const latestOnly = boolArg(args, 'latestOnly');
      const startDate = dateTimeArg(args, 'startDate');
      const limit = intArg(args, 'limit', 1, MAX_LIMIT);
      const includeChecks = boolArg(args, 'includeChecks') ?? true;
      const response = await listPostureReports(creds!, { tenantId, latestOnly, startDate, limit });
      if (includeChecks) return textResult(response);
      const reports = (response.reports ?? []).map(({ checks: _omitted, ...rest }) => rest);
      return textResult({ ...response, reports });
    }

    return errorResult(`Unknown security tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}

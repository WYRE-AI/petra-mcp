import type { ToolAnnotations } from '@modelcontextprotocol/sdk/types.js';
import type { PetraCredentials } from '../types.js';
import type { CallToolResult } from './types.js';

export function textResult(value: unknown): CallToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] };
}

export function errorResult(message: string): CallToolResult {
  return { content: [{ type: 'text', text: `Error: ${message}` }], isError: true };
}

/** Returns an error CallToolResult if credentials are missing, else null. */
export function requireCredentials(creds: PetraCredentials | null): CallToolResult | null {
  if (!creds) {
    return errorResult('No Petra Security API key configured. Set PETRA_API_KEY (Petra portal > Settings > API Keys).');
  }
  return null;
}

/** Every tool on this server is a read-only GET against Petra. */
export const READ_ONLY_ANNOTATIONS: ToolAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
};

/** Thrown by the argument validators below; surfaced to the caller as a tool error. */
export class ArgumentError extends Error {}

const TENANT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const ISO_DATE_TIME_RE = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?(Z|[+-]\d{2}:?\d{2})?)?$/;

export function optionalString(args: Record<string, unknown>, name: string): string | undefined {
  const value = args[name];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string') throw new ArgumentError(`${name} must be a string.`);
  const trimmed = value.trim();
  return trimmed === '' ? undefined : trimmed;
}

/** Petra tenant ID (e.g. ZZk90t) or Microsoft tenant GUID. */
export function tenantIdArg(args: Record<string, unknown>, required: true): string;
export function tenantIdArg(args: Record<string, unknown>, required?: false): string | undefined;
export function tenantIdArg(args: Record<string, unknown>, required = false): string | undefined {
  const value = optionalString(args, 'tenantId');
  if (value === undefined) {
    if (required) throw new ArgumentError('tenantId is required. Use petra_list_tenants to find it.');
    return undefined;
  }
  if (!TENANT_ID_RE.test(value)) {
    throw new ArgumentError('tenantId must be a Petra tenant ID (e.g. ZZk90t) or a Microsoft tenant ID (GUID).');
  }
  return value;
}

/** ISO 8601 date or date-time, validated to a real instant. */
export function dateTimeArg(args: Record<string, unknown>, name: string): string | undefined {
  const value = optionalString(args, name);
  if (value === undefined) return undefined;
  if (!ISO_DATE_TIME_RE.test(value) || Number.isNaN(Date.parse(value))) {
    throw new ArgumentError(`${name} must be an ISO 8601 date (2026-03-01) or date-time (2026-03-01T00:00:00Z).`);
  }
  return value;
}

/** ISO date only (YYYY-MM-DD). */
export function dateArg(args: Record<string, unknown>, name: string): string | undefined {
  const value = optionalString(args, name);
  if (value === undefined) return undefined;
  if (!ISO_DATE_RE.test(value) || Number.isNaN(Date.parse(value))) {
    throw new ArgumentError(`${name} must be a date in YYYY-MM-DD format.`);
  }
  return value;
}

export function intArg(args: Record<string, unknown>, name: string, min: number, max: number): number | undefined {
  const value = args[name];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
    throw new ArgumentError(`${name} must be an integer between ${min} and ${max}.`);
  }
  return value;
}

export function boolArg(args: Record<string, unknown>, name: string): boolean | undefined {
  const value = args[name];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'boolean') throw new ArgumentError(`${name} must be true or false.`);
  return value;
}

export const TENANT_ID_DESCRIPTION =
  'Petra tenant ID (from petra_list_tenants, or the app.petrasecurity.com/tenant/<id> URL) or the Microsoft tenant ID; Petra resolves either.';

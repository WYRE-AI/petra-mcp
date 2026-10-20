import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { SECURITY_TOOLS, handleSecurityTool } from './security.js';
import { TENANT_TOOLS, handleTenantTool } from './tenants.js';
import type { CallToolResult } from './types.js';

export const ALL_TOOLS: Tool[] = [...TENANT_TOOLS, ...SECURITY_TOOLS];

const TENANT_NAMES = new Set(TENANT_TOOLS.map((t) => t.name));
const SECURITY_NAMES = new Set(SECURITY_TOOLS.map((t) => t.name));

export async function dispatchToolCall(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  if (TENANT_NAMES.has(name)) return handleTenantTool(name, args);
  if (SECURITY_NAMES.has(name)) return handleSecurityTool(name, args);
  return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
}

/**
 * Petra Security API credential. Created by a Petra Admin under
 * Settings > API Keys in app.petrasecurity.com. The full key value is only
 * shown once at creation and cannot be retrieved later.
 */
export interface PetraCredentials {
  apiKey: string;
}

export type QueryValue = string | number | boolean | undefined;

/** Tenant reference embedded in incidents, failed-attack reports and posture reports. */
export interface PetraTenantRef {
  petraTenantId?: string;
  name?: string;
  microsoftTenantId?: string;
  [key: string]: unknown;
}

/** GET /v1/tenants item. */
export interface PetraTenant extends PetraTenantRef {
  isPaused?: boolean;
  onboardingDate?: string;
}

export interface PetraTenantsResponse {
  totalTenants?: number;
  tenants?: PetraTenant[];
  [key: string]: unknown;
}

/** GET /v1/incidents item. */
export interface PetraIncident {
  id?: string;
  url?: string;
  createdAt?: string;
  occurredAt?: string;
  remediationStatus?: string;
  isLive?: boolean;
  dwellTimeMinutes?: number;
  tenant?: PetraTenantRef;
  user?: {
    id?: string;
    userPrincipalName?: string;
    mail?: string;
    displayName?: string;
    accountEnabled?: boolean;
    lastPasswordChangeDateTime?: string | null;
    [key: string]: unknown;
  };
  phishingEmail?: Record<string, unknown> | null;
  [key: string]: unknown;
}

export interface PetraIncidentsResponse {
  incidents?: PetraIncident[];
  [key: string]: unknown;
}

/** GET /v1/failed-attacks. */
export interface PetraFailedAttacksResponse {
  dateRange?: { startDate?: string; endDate?: string };
  tenant?: PetraTenantRef;
  totalCount?: number;
  byCountry?: Record<string, unknown>[];
  byDay?: Record<string, unknown>[];
  topTargetedUsers?: Record<string, unknown>[];
  [key: string]: unknown;
}

/** GET /v1/usage tenant row. */
export interface PetraTenantUsage {
  petraTenantId?: string;
  microsoftTenantId?: string;
  onboardingDate?: string;
  displayName?: string;
  service?: string;
  isPaused?: boolean;
  firstBillableDate?: string;
  billableStatus?: string;
  totalLicensedUsers?: number;
  billableUsersThisMonth?: number;
  proratingPercentageThisMonth?: number;
  [key: string]: unknown;
}

export interface PetraUsageResponse {
  asOf?: string;
  reportGeneratedAt?: string;
  organizationName?: string;
  totalTenants?: number;
  tenants?: PetraTenantUsage[];
  [key: string]: unknown;
}

/** GET /v1/billable-users. */
export interface PetraBillableUsersResponse {
  tenantId?: string;
  tenantDisplayName?: string;
  microsoftTenantId?: string;
  reportGeneratedAt?: string;
  totalBillableUsers?: number;
  projectedBillableUnitsThisMonth?: number;
  users?: Record<string, unknown>[];
  [key: string]: unknown;
}

/** GET /v1/posture-reports. */
export interface PetraPostureReportsResponse {
  totalReports?: number;
  reports?: Record<string, unknown>[];
  [key: string]: unknown;
}

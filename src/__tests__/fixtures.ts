/** Response bodies taken from the examples in Petra's published OpenAPI spec (api-reference/openapi.json). */
export const TENANTS = {
  totalTenants: 2,
  tenants: [
    {
      petraTenantId: 'ZZk90t',
      name: 'Acme Corporation',
      microsoftTenantId: 'a1b2c3d4-5e6f-7890-abcd-ef1234567890',
      isPaused: false,
      onboardingDate: '2025-01-15T00:00:00.000Z',
    },
    {
      petraTenantId: 'Y3mPqr',
      name: 'Globex Inc.',
      microsoftTenantId: 'ffff0000-1111-2222-3333-444455556666',
      isPaused: true,
      onboardingDate: '2024-09-02T00:00:00.000Z',
    },
  ],
};

export const INCIDENTS = {
  incidents: [
    {
      id: 'a212087c-bc60-4fbc-8bf5-5a4c2f823e5f',
      url: 'https://app.petrasecurity.com/tenant/ZZk90t/incidents/a212087c-bc60-4fbc-8bf5-5a4c2f823e5f',
      createdAt: '2026-01-20T12:33:15.000Z',
      occurredAt: '2026-01-20T12:28:47.000Z',
      remediationStatus: 'REMEDIATED',
      isLive: true,
      dwellTimeMinutes: 4.48,
      tenant: { petraTenantId: 'ZZk90t', name: 'Acme Corp.', microsoftTenantId: '' },
      user: { id: 'u1', userPrincipalName: 'asha.streich@acmecorp.com', mail: 'asha.streich@acmecorp.com', displayName: 'Asha Streich' },
      phishingEmail: { subject: 'Shared "Due Pay Application" with you', sender: { address: 'brad.smith@conedaccting.com' } },
    },
    {
      id: '0776897d-be9d-4785-82b1-e240e64f2476',
      url: 'https://app.petrasecurity.com/tenant/ZZk90t/incidents/0776897d-be9d-4785-82b1-e240e64f2476',
      createdAt: '2026-07-19T16:55:41.242Z',
      occurredAt: '2026-05-21T17:11:00.000Z',
      remediationStatus: 'REMEDIATED_PRIOR_TO_ONBOARDING',
      isLive: false,
      dwellTimeMinutes: 60560.75,
      tenant: { petraTenantId: 'ZZk90t', name: 'Acme Corp.', microsoftTenantId: '' },
      user: { id: 'u2', userPrincipalName: 'fleta.rowe@acmecorp.com', mail: 'fleta.rowe@acmecorp.com', displayName: 'Fleta Rowe' },
      phishingEmail: null,
    },
  ],
};

export const FAILED_ATTACKS = {
  dateRange: { startDate: '2025-01-05T00:00:00.000Z', endDate: '2025-02-25T00:00:00.000Z' },
  tenant: { petraTenantId: 'ZZk90t', name: 'Acme Corp.', microsoftTenantId: 'a1b2c3d4-5e6f-7890-abcd-ef1234567890' },
  totalCount: 50471,
  byCountry: [{ name: 'United States', countryCode: 'US', count: 11501 }],
  byDay: [{ date: '2025-01-05T00:00:00.000Z', byType: [{ attackType: 'LEGACY_AUTH', count: 11 }] }],
  topTargetedUsers: [{ userPrincipalName: 'pink.jones@acmecorp.com', count: 4463, attackOriginCountries: [] }],
};

export const USAGE = {
  asOf: '2026-03-01',
  reportGeneratedAt: '2026-03-01T12:00:00.000Z',
  organizationName: 'Example MSP',
  totalTenants: 3,
  tenants: [
    { petraTenantId: 'ZZk90t', displayName: 'Acme', service: 'Monitoring', isPaused: false, billableStatus: 'Active', totalLicensedUsers: 40, billableUsersThisMonth: 38 },
    { petraTenantId: 'Y3mPqr', displayName: 'Globex', service: 'Monitoring', isPaused: true, billableStatus: 'Active', totalLicensedUsers: 20, billableUsersThisMonth: 20 },
    { petraTenantId: 'Q9trial', displayName: 'Initech', service: 'Autopsy', isPaused: false, billableStatus: 'Trial', totalLicensedUsers: 5, billableUsersThisMonth: 0 },
  ],
};

export const BILLABLE_USERS = {
  tenantId: 'ZZk90t',
  tenantDisplayName: 'Acme Corporation',
  microsoftTenantId: 'a1b2c3d4-5e6f-7890-abcd-ef1234567890',
  reportGeneratedAt: '2026-01-06T12:00:00.000Z',
  totalBillableUsers: 2,
  projectedBillableUnitsThisMonth: 2,
  users: [
    { id: 'user-id-1', displayName: 'John Doe', userPrincipalName: 'john.doe@example.com', accountEnabled: true, assignedLicenseSkuIds: ['sku-1'] },
    { id: 'user-id-2', displayName: 'Jane Off', userPrincipalName: 'jane.off@example.com', accountEnabled: false, assignedLicenseSkuIds: ['sku-1'] },
  ],
};

export const POSTURE = {
  totalReports: 1,
  reports: [
    {
      id: '7c1a4a1e-3b2f-4a55-9d7e-1f0c2b3d4e5f',
      tenant: { petraTenantId: 'ZZk90t', name: 'Acme Corp.' },
      reportType: 'FOLLOW_UP',
      score: 81,
      grade: 'B',
      topRisks: [{ controlId: 'blockLegacyAuth', status: 'OPEN', severity: 'CRITICAL' }],
      checks: [{ controlId: 'blockLegacyAuth', status: 'OPEN' }],
    },
  ],
};

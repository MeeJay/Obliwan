// Master / default tenant — the "god view".
//
// The default tenant (seeded with id=1 in migration 001) acts as a god view:
// when the active session tenant is the master, operational data from ALL
// tenants is visible (sites, devices, groups, snapshots, drift, jobs).
//
// Identity is positional (id === 1), matching the rest of the Obli* suite —
// there is no is_master column. Null/undefined are treated as "not master" so
// a missing tenant never accidentally grants god view.
//
// SECURITY RULE: god view applies to OPERATIONAL data only. Credentials and
// secrets (device transport secrets, SMTP passwords, SNMP communities,
// notification channel configs, Obligate API key) stay tenant-scoped even for
// the master tenant, and revealing one still requires SECRET_READ.

export const MASTER_TENANT_ID = 1;

export function isMasterTenant(tenantId: number | null | undefined): boolean {
  return tenantId === MASTER_TENANT_ID;
}

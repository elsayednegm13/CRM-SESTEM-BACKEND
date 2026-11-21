# SECURITY-F06-TEAM-ROLE-ADMIN-REMEDIATION-01 — attempt ledger

## 2026-10-26 — W0/G1/G2 source gate

- W0 was read-only: five Git HEADs/branches/status, approved `CLAUDE.md` SHA, prior 90-file manifest and payload, PHP `pdo_pgsql`, and Docker server availability were checked. No database or container was contacted, started, or modified.
- G1 traced the actual `role.manage`, `member.manage`, `role.view`, and `member.view` routes/services and the Actor Scope fixture. The only ON credential mappings in `config/f06_actor_sql.php` are the A1/A2/B1/A4 synthetic roles. The current fixture grants those actors only `leads.view` and `leads.manage`; it has no `role.manage`, `member.manage`, `member.view`, or `role.view` grant.
- G2 decision: `STOP_SCOPE_AUTH_REQUIRED`. An independent authorized admin actor cannot authenticate under FLAG ON without modifying the forbidden config/resolver/middleware surface. Adding admin privileges to A1 merely to pass the gate would change the tested authority fixture without a legitimate admin identity. Therefore no SQL overlay, application change, sandbox, migration, or HTTP test was begun.
- Minimum next authorization: define a synthetic company-admin actor and its identity/credential mapping through an explicitly approved config/resolver change or provide an existing actor with verified legitimate admin grants; then review the selected operation's definer, audit, invariant, version, and RLS contract before execution. The new grant must originate from a trusted provisioning path, never from an actor's own SQL write.
- No prior evidence or resources were changed. This ledger is the only tool-file output of this attempt.

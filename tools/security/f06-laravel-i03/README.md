# F06 Laravel I03 isolated sandbox evidence

All scripts in this directory are scoped to `SECURITY-F06-LARAVEL-IMPLEMENT-03-UNBLOCK-01`. They use only the labelled `daleel-f06-laravel-i03-49ec7da0-pg` container and the runtime directory named in the report. Never run them against an unverified target. The SQL overlays are sandbox fixtures, not product migrations.

Order used: `g0_preflight.php`, `bootstrap.py` / `provision_retry.py` / `migrate_retry.py` / `resume.py`, `sql_gate.py`, and `http_gate.py`. The HTTP runner has an optional `--missing-a4` negative control. It creates local session and cookie artifacts outside this repository and restores Lead rows after each flag. `tls_proxy.py` terminates local HTTPS for Laravel's secure testing cookies. Logs and JSON here are redacted; raw runtime artifacts remain outside the repository.

The final full HTTP evidence is `http_gate_evidence_20261026T055016.json`; 23 OFF and 23 ON scenarios passed. The missing credential control is `http_gate_evidence_20261026T054602.json` (A4 read returned 500 and A1 stayed 200). `sql_gate_evidence.json` contains the latest SQL gate run. `a4_pg_connections.redacted.log` contains only scrubbed PostgreSQL A4 authentication lines. See `ATTEMPT-LEDGER.md` for failed attempts and recovery.

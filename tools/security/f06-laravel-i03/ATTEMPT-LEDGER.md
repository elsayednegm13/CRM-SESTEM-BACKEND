# Attempt ledger — I03 only

The initial bootstrap was rejected because a Windows bind-mounted `.pgpass` appeared as mode 0777 inside Linux. The runner now copies the file through stdin into the labelled container and sets mode 0600. HBA remained SCRAM-only.

The first migration invocation failed because Laravel interpreted a Windows absolute cache path as repository-relative. The next invocation used an available WinGet PHP without `pdo_pgsql`. A pinned Herd PHP and a sibling runtime cache path fixed those harness issues. Migrations then reached 27/38 and stopped at migration 028: provider authentication/control had been mapped to one sandbox login role. The I03 provisioner added two separate least-privilege synthetic provider roles; migration retry reached 38/38. No migration source file changed.

The first SQL gate run exposed harness parsing errors: PostgreSQL emitted `false:true:false` for role membership options, and an error prefix was parsed as a SQLSTATE. The gate was corrected and rerun with 21/21 expected results and matching before/after Lead fingerprint.

The HTTP harness initially received 404 for a valid tenant because `artisan serve` reloaded a child process without the sandbox environment. `--no-reload` corrected this. Testing cookies were Secure, so a loopback HTTPS proxy was added. A login rotates CSRF, requiring a second `/sanctum/csrf-cookie` read before PATCH. These are harness changes, not application changes.

An additional HTTP run after enabling PostgreSQL connection logging passed its OFF scenarios, but the harness rejected a stopped Windows socket held in `TIME_WAIT` and skipped fixture restoration. The following run detected the changed A4 list (2 instead of 1). Only the two known synthetic Lead rows were reset to their fixture semantics; new before/after fingerprints were captured. Subsequent repeats received 429 for suspended A3 due to persisted test rate-limit cache. Per-run and per-flag storage paths resolved this. The final complete HTTP run passed 23/23 OFF and 23/23 ON and restored each baseline. All failed runs remain recorded here; their partial JSON files are not a PASS.

A targeted historical Unit test invocation was interrupted after more than 30 seconds without output from host `php artisan test`; it supplies no historical pass count. The historical suites remain blocked by static target guards and lifecycle risk as described in the report.

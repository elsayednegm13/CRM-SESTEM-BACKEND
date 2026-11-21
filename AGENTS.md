# Daleel CRM API repository instructions

- Follow the currently approved control and the contracts in `docs/`.
- This foundation contains transport and infrastructure conventions only. Do not add business models, tables, migrations, seeds, authentication flows, tenant policies, or integrations without a separately approved control.
- Do not run `artisan migrate`, create a database, or connect to production/staging from this repository unless a later control explicitly authorizes it.
- Do not add Composer packages without documenting why Laravel built-ins are insufficient and the security/maintenance impact. Optional agent tooling is not a prerequisite.
- Keep CORS exact-origin and credential-safe. Never log request bodies, credentials, tokens, cookies, or payment data. Preserve safe API errors and request IDs.
- Keep the three frontend repositories untouched. Do not stage, commit, push, deploy, or rewrite Git history unless expressly authorized.

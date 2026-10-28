# Publication note

Approved changes are merged into `main`, and the static interface is published on GitHub Pages: https://swopnab.github.io/JWT-auth-service-plus-RBAC/showcase.html. GitHub Pages hosts the updated interface. The existing Cloudflare Worker and D1 are unchanged; the new backend release is deferred. Compatibility controls withhold unavailable session features.

The review below records pre-publication validation and its remaining limits.

# SwopMobile — reusable authentication review

Status: local review, no push or deployment yet. Existing public service configuration was preserved; no remote account or database was changed.

## Existing functionality retained

The project already had registration, password hashing, JWT access, refresh credentials, device sessions, role data, per-user jobs/favorites/settings, and account screens. The unpublished token-security patch already implemented strong token digests, atomic refresh consumption, replay revocation, active-session checks, and shared database rate limits. This release builds on it instead of rebuilding those features.

## New scope

- `client/example/` is a separate small application using the same `client/js/api.js` adapter. It registers, logs in, fetches protected profile/favorites, restores access after reload, and logs out. The example only connects locally. There is no second authentication backend.
- Existing session screens now identify the current session. `DELETE /user/sessions` and its `/sessions` alias revoke only the caller’s sessions; the previously dangling revoke-all UI is connected. Access tokens for revoked sessions fail on the next protected request.
- Login/registration reject malformed credential types; malformed/non-object JSON produces a client error. Ownership and role tests cover ID manipulation. Session labels are escaped before rendering.
- The account UI uses larger readable text, calm blue/neutral surfaces, clear focus outlines, reduced motion, and no remote font requirement. `client/showcase.html` explains the service and includes an actual local fictional-account screenshot.
- The Pages workflow builds and uploads only `client/dist`, replacing the whole-repository artifact. API source, migrations, secrets, and databases are not public site assets. The root-level legacy HTML/JS copies remain for historical compatibility but are not the deployment source; edit `client/`.

## Actual permissions matrix

| Capability | User | Moderator | Admin |
|---|---|---|---|
| Own profile/settings/jobs/favorites/sessions | Yes | Yes | Yes |
| Other users’ private jobs/favorites | No | No | No |
| GET admin account list and role details | No | No | Yes |
| Edit roles or moderate accounts through an API | Not implemented | Not implemented | Not implemented |

Seed permission names such as `users.write` and `audit.read` are metadata, not proof of an implemented or guarded endpoint. The currently implemented admin routes explicitly require Admin. A role label must not advertise unavailable moderation features.

## Local setup

Follow the root README for `npm ci`, local migrations, fictional seed data, and `.dev.vars` using your own random secret. Never seed demo accounts into a real database. All commands here target local development.

For an entirely isolated route/SQLite test harness:

```sh
npm ci
node api/tests/local-server.js
# separate terminal
npm run dev:client
```

Open `http://localhost:5173/example/index.html` or `/showcase.html`. The harness uses temporary SQLite and public fixture-only credentials. It is not a deployable service. The ordinary setup uses Wrangler/D1; this harness only adapts the D1 methods needed by the real Hono handlers.

The existing main account pages retain the established remote API URL on non-local hosts. This release does not approve a new hosted architecture or change live credentials. The new integration example refuses remote API use. Email delivery is still a console-only development implementation, not a working email service. The verification token URL and email-verification requirement need a separate product decision before hosting real users.

## Authentication in plain language

Registration stores a salted PBKDF2 password hash. Login returns a signed short-lived access token plus a random rotating refresh token. The database stores refresh-token digests. Protected handlers validate the access signature/expiry and active session, load current roles from the database, and constrain private SQL queries by the authenticated user ID. Refresh consumes one token atomically; replay revokes that session. Logout or revoke-all deletes the relevant session, invalidating associated access on subsequent requests.

The browser adapter uses sessionStorage; script injection can expose its tokens. Refresh/session behavior, password-hash work factors, hosted cookie/CSRF architecture, secret management, logging, and abuse controls require a full deployment review before production claims. This release does not invent encryption, add a paid provider, or claim production readiness.

## API checks

```sh
npm test
npm run build:client
postman collection run postman/swopmobile.postman_collection.json --reporters cli --bail
```

The collection uses only the fictional `api/tests/local-server.js` accounts. It checks successful requests, invalid JSON/types, expired JWTs, forbidden Admin access, cross-user reads/updates, refresh, and revocation. Tokens are temporary collection variables; never export real credentials into Git. Collection generation: `node postman/generate-collection.mjs`.

Actual local Workers/D1 verification used a separate temporary persistence directory, all five migrations, the repository’s fictional seed data, a fixture-only signing key, and Wrangler `dev --local`. The same collection was run with `--env-var baseUrl=http://127.0.0.1:8792`. Both harness and local Workers runs passed all 17 assertions. Postman ran locally without cloud login or publishing results. GitHub Actions checks are prepared, but no new remote CI run is claimed before push approval.

## Interview explanation

“I reused one API adapter in a separate example app to demonstrate integration. I tested authorization by changing IDs and roles, rather than trusting hidden frontend buttons. I connected session revocation end to end and ran the same Postman contract against both a small SQLite harness and the actual local Workers/D1 runtime. I can explain why a valid JWT must also reference a still-active session.”

## Publishing dependency

Do not publish the new client alone against an old API contract. The current-session metadata and revoke-all screen depend on the reviewed API update. Before any separately approved hosted rollout, export/backup D1 and confirm the existing secure deployment configuration, then coordinate API migration and static-client release. Security migration 0005 intentionally invalidates legacy weak token digests; affected sessions must log in again. It preserves account/application record IDs. No remote migration or deployment was performed in this review.

## Existing tracked database discovered during privacy review

The original repository tracked `zabum-backend/storage/zabum.db` (conversation/message/memory tables). It has been removed from the proposed Git index, **not deleted locally**. An identical local backup is kept at `.local-backups/legacy-zabum-preserved.db`; both paths are ignored. No record contents were displayed or included in screenshots. Old published Git history still contains the file. History rewriting/removal has not been authorized or performed; it needs a separate coordinated decision if private content must be removed from published history. The revised Pages artifact excludes backend storage entirely.

## Checks run for this review

19 Node API/client checks and 4 standalone browser scenarios passed. All 17 Postman assertions passed against both the offline SQLite harness and the actual local Workers/D1 runtime. All five migrations applied to a separate temporary local D1 database. The client production build passed. No remote database, hosted API, GitHub CI run, or public deployment was modified. Compiled Python caches were also removed from tracking while kept locally; the source modules recreate them when needed.

Pages publication is now an explicit workflow dispatch so code updates cannot deploy a new client ahead of its matching API migration. Run it only after the coordinated API release succeeds.

Pages-only release approved: the existing hosted Worker remains unchanged. The session screen detects the earlier API by absent current-session metadata, explains its delayed access-token revocation, and withholds the unsupported revoke-all action. The showcase distinguishes tested source changes from the live backend. No remote D1 migration or Worker deployment was performed.

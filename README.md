# JWT Authentication and RBAC Service

This project is a authentication and authorization demo built with Cloudflare Workers (API) and a vanilla JavaScript frontend. I built this to have a solid starting point for handling user logins, sessions, and role-based access control (RBAC).

## What's included

The codebase is split into two main parts:
1. **client**: A vanilla HTML/CSS/JS frontend that handles user registration, login, and displaying a protected dashboard.
2. **api**: A Cloudflare Worker built with Hono and D1 (SQLite) for the backend. It handles JWT access tokens and opaque refresh tokens, password hashing (using Web Crypto PBKDF2), and user permissions.

## Getting started

You'll need Node.js 24 LTS installed to run this project locally.

First, install all the dependencies:
`npm install`

Copy `api/.dev.vars.example` to `api/.dev.vars` and replace its placeholder with a random secret:

```sh
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Keep that secret local. For a future deployment, set it with `wrangler secret put JWT_ACCESS_SECRET`; it is intentionally absent from public configuration.

Since this uses Cloudflare D1 for the database, you need to set up the local database tables and seed them with some default roles (Admin, User, Moderator). Run these commands:
`npm run db:migrate:local`
`npm run db:seed:local`

After the database is ready, you can start the development servers for both the frontend and the backend at the same time:
`npm run dev:api`
`npm run dev:client`

The client will be running at http://localhost:5173 and the API runs at http://localhost:8787.

## Demo accounts

If you ran the seed script, you can log in with any of these test accounts (password is Password123! for all of them):
- admin@example.com
- moderator@example.com
- user@example.com

## How it works

When a user logs in, the API issues a short-lived access token and a long-lived refresh token. The frontend stores these and attaches the access token to API requests. The backend uses the D1 database to verify credentials, check roles, and enforce permissions on protected routes. I also included a sample music player app in the client to demonstrate how protected API endpoints work in practice.

## Verification

Run `npm test` for SQL-backed integration tests using Node's built-in SQLite. They exercise hashing, refresh races/replay/expiry, logout, password resets, role checks, cross-user job ownership, and persistent rate limits. CI also builds the client and applies every local D1 migration. Tests run without cloud credentials, a paid service, or a deployed database.

## Session and deployment behavior

Access tokens contain a session ID. Every protected request checks that session in D1 and reloads current roles. Logout, session deletion, and password changes therefore invalidate existing access immediately. Refresh tokens are single-use; replay revokes the session. Clients must serialize refresh calls rather than refreshing in parallel.

Opaque refresh/reset/verification tokens use SHA-256 digests. Migration 0005 invalidates the old 32-bit token hashes; existing users must sign in again and request fresh reset/verification links. The migration commands now apply all pending migrations, not only the initial schema. Apply migrations before deploying API changes. No cloud deployment is performed by the test workflow.

Rate limits use atomic D1 counters shared across worker instances, with fixed time windows, hashed client keys, expiry cleanup, and Retry-After responses. Cloudflare's trusted IP header is used; locally, requests share a local bucket. Database failures fail closed. Fixed windows allow bursts near a window boundary.

The frontend retains its bearer-token design. Tokens accessible to JavaScript remain exposed to XSS; this demo should not be described as a completed security audit. A future cookie migration needs an explicit cross-origin/CSRF design and coordinated client changes. Email delivery uses the configured provider and is separate from these local tests.

Static publishing uses the existing GitHub Pages workflow on main. The redundant gh-pages CLI dependency was removed; `npm run build:client` still produces the client build for preview.

## Review release

See [current architecture, permissions matrix, integration example, API checks, and limitations](docs/RELEASE_REVIEW.md). Use `client/showcase.html` for the project explanation and `client/example/index.html` for the separate local integration app. `client/` is the deployment source; legacy root copies are not published by the updated workflow.

## Published interface — October 28, 2026

[Open the website](https://swopnab.github.io/JWT-auth-service-plus-RBAC/showcase.html). GitHub Pages hosts the updated interface. The existing Cloudflare Worker and D1 are unchanged; the new backend release is deferred. Compatibility controls withhold unavailable session features. See GitHub Actions for release checks and deployment status.

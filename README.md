# JWT Authentication and RBAC Service

This project is a complete authentication and authorization system built with Cloudflare Workers (API) and a vanilla JavaScript frontend. I built this to have a solid starting point for handling user logins, sessions, and role-based access control (RBAC).

## What's included

The codebase is split into two main parts:
1. **client**: A vanilla HTML/CSS/JS frontend that handles user registration, login, and displaying a protected dashboard.
2. **api**: A Cloudflare Worker built with Hono and D1 (SQLite) for the backend. It handles JWT token generation (access and refresh tokens), password hashing (using Web Crypto PBKDF2), and user permissions.

## Getting started

You'll need Node.js installed to run this project locally.

First, install all the dependencies:
`npm install`

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

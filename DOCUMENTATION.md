# SwopMobile Platform Documentation
**Comprehensive Technical Architecture, API Reference, RBAC Specification, and Setup Guide**

---

## Table of Contents

1. [Executive Overview](#1-executive-overview)
2. [System Architecture](#2-system-architecture)
3. [Frontend Applications & Dashboard](#3-frontend-applications--dashboard)
   - [3.1 Authentication & Session Management](#31-authentication--session-management)
   - [3.2 SwopMobile Hub Dashboard](#32-swopmobile-hub-dashboard)
   - [3.3 Audius Music Player](#33-audius-music-player)
   - [3.4 Zabum AI Assistant](#34-zabum-ai-assistant)
4. [Backend Services & APIs](#4-backend-services--apis)
   - [4.1 Cloudflare Worker (Auth & Core Services)](#41-cloudflare-worker-auth--core-services)
   - [4.2 Zabum AI Flask Backend](#42-zabum-ai-flask-backend)
5. [Role-Based Access Control (RBAC) Specification](#5-role-based-access-control-rbac-specification)
   - [5.1 Roles Matrix](#51-roles-matrix)
   - [5.2 Permissions Matrix](#52-permissions-matrix)
   - [5.3 Authorization Enforcement Flow](#53-authorization-enforcement-flow)
6. [Data Isolation & Security Model](#6-data-isolation--security-model)
   - [6.1 User Isolation Rules](#61-user-isolation-rules)
   - [6.2 Cryptography & Tokens](#62-cryptography--tokens)
7. [Database Schemas & Migrations](#7-database-schemas--migrations)
   - [7.1 Cloudflare D1 Schema (SQLite)](#71-cloudflare-d1-schema-sqlite)
   - [7.2 Zabum AI SQLite Schema](#72-zabum-ai-sqlite-schema)
8. [API Endpoint Reference](#8-api-endpoint-reference)
   - [8.1 Authentication Endpoints](#81-authentication-endpoints)
   - [8.2 User & Profile Endpoints](#82-user--profile-endpoints)
   - [8.3 Session Management Endpoints](#83-session-management-endpoints)
   - [8.4 User Data Endpoints (Settings, Jobs, Favorites)](#84-user-data-endpoints-settings-jobs-favorites)
   - [8.5 Zabum AI Endpoints](#85-zabum-ai-endpoints)
9. [Local Development & Deployment Guide](#9-local-development--deployment-guide)
   - [9.1 Prerequisites](#91-prerequisites)
   - [9.2 Initial Setup & Seeding](#92-initial-setup--seeding)
   - [9.3 Running Local Servers](#93-running-local-servers)
   - [9.4 Production Deployment](#94-production-deployment)
10. [Troubleshooting & FAQ](#10-troubleshooting--faq)

---

## 1. Executive Overview

**SwopMobile** (repository: `Swopnab/JWT-auth-service-plus-RBAC`) is a secure, serverless cloud platform combining **JWT Authentication**, granular **Role-Based Access Control (RBAC)**, multi-app workspace management, integrated **Audius Music Streaming**, and private **Local AI Intelligence (Zabum AI)** powered by Llama 3.2.

### Core Highlights
* **Zero Trust Frontend**: Client claims are never trusted; user identities and permission capabilities are cryptographically signed via JWTs and validated against server-side database records.
* **Tab-Scoped Session Security**: Tokens and session identities reside in browser `sessionStorage`, ensuring sessions automatically terminate upon closing browser tabs/windows while persisting through page refreshes.
* **Serverless Backend**: High-performance Cloudflare Worker written in modern vanilla ES modules with Hono framework backed by Cloudflare D1 distributed SQLite.
* **Granular Multi-Tenant Isolation**: Strict per-user isolation guarantees users can only access, modify, or delete their own data across jobs, settings, favorites, conversations, and AI memories.
* **Dual AI Architecture**: Decoupled architecture where the Flask AI backend verifies JWTs directly with the Cloudflare Auth Worker without sharing database secrets or JWT signing keys.

---

## 2. System Architecture

```text
                                  ┌──────────────────────────────────────────────┐
                                  │           SwopMobile Frontend (Client)       │
                                  │      (GitHub Pages / Vite Vanilla JS)        │
                                  │                                              │
                                  │  • dashboard.html (Categorized Hub)          │
                                  │  • ai-assistant.html (Zabum AI Chat)         │
                                  │  • music-player.html (Audius Streamer)       │
                                  │  • sessions.html (Active Session Manager)    │
                                  │  • index.html, register.html, auth flows     │
                                  └───────────────┬──────────────────────┬───────┘
                                                  │                      │
                   1. Direct Auth, CRUD, & RBAC   │                      │  3. AI Inference & Memory
                      Authorization: Bearer <JWT> │                      │     Authorization: Bearer <JWT>
                                                  ▼                      ▼
                     ┌────────────────────────────────────────┐ ┌────────────────────────────────┐
                     │   Cloudflare Auth Worker (Port 8787)   │ │  Zabum AI Flask (Port 5001)    │
                     │          Hono API Framework            │ │   (Local Python Assistant)     │
                     └───────────────────┬────────────────────┘ └──────────────┬─────────────────┘
                                         │                                     │
                                         │ 2. SQL Queries                      │ 4. GET /auth/verify
                                         ▼                                     ▼
                     ┌────────────────────────────────────────┐ ┌────────────────────────────────┐
                     │     Cloudflare D1 Database (SQLite)    │ │   Cloudflare Auth Worker API   │
                     │                                        │ └────────────────────────────────┘
                     │ • users & credentials (PBKDF2)         │                │
                     │ • roles, permissions, role_permissions │                │ 5. Local LLM Context
                     │ • sessions, user_settings              │                ▼
                     │ • jobs & favorites (per user_id)       │ ┌────────────────────────────────┐
                     │                                        │ │    Ollama Service (Port 11434) │
                     └────────────────────────────────────────┘ │       Llama 3.2 Model          │
                                                                └────────────────────────────────┘
```

---

## 3. Frontend Applications & Dashboard

### 3.1 Authentication & Session Management
All authenticated pages (`dashboard.html`, `ai-assistant.html`, `music-player.html`, `sessions.html`) enforce protection using the client-side router guard `requireAuth()`.

* **Token Storage**: Stored exclusively in browser `sessionStorage`:
  * `accessToken`: Short-lived JWT (15-minute lifespan).
  * `refreshToken`: High-entropy cryptographically generated random hex string (7-day lifespan).
  * `user`: Cached user profile JSON object.
* **Auto-Refresh**: If an API request encounters an expired token or HTTP 401, `apiRequest()` automatically invokes `/auth/refresh` behind the scenes, transparently retrying the request without user interruption.
* **Logout Cleanup**: `clearAuth()` clears all tokens and session entries and redirects immediately to `index.html`.

### 3.2 SwopMobile Hub Dashboard (`dashboard.html`)
The dashboard organizes all user applications and public repositories into distinct categories:

1. **Header & Brand**: Modern dark aesthetic with `SwopMobile` branding, session shortcut, authenticated email display, and one-click logout.
2. **Greeting & Inline Nickname Editor**: Displays user nickname (fallback to email) with live inline editing that updates Cloudflare D1 without page reloads.
3. **Compact Status Bar**: Displays Email Verification status, Role badges (e.g., `Admin`, `User`), and Total Permission Count.
4. **Permissions Details Strip**: Directly beneath the status bar, renders active user permissions as compact pills (e.g., `users.read`, `use_ai_assistant`).
5. **Categorized Application Grids**:
   * **⭐ Featured Apps**: Built-in authenticated applications (**Zabum AI Assistant** and **Music Player**).
   * **🎮 Games**: Hand-Controlled Racing Simulation, Rock Paper Scissors, etc.
   * **💼 Apps**: Personal Job Tracker, Portfolio Website, React Blog, etc.
   * **🎵 Entertainment**: Dedicated audio/entertainment tools.
6. **Universal Search Filter**: Filters across project titles, descriptions, programming languages, and categories in real-time, automatically hiding empty categories.
7. **Floating Zabum AI Bubble**: Fixed bottom-right glowing action bubble allowing instant launch into the AI assistant workspace.

### 3.3 Audius Music Player (`music-player.html`)
A protected music streaming application:
* Searches Audius decentralised streaming network for artists and track titles.
* Displays artwork, durations, artist metadata, and streaming audio playback.
* Features trending tracks, custom playback controls, volume slider, and track queues.

### 3.4 Zabum AI Assistant (`ai-assistant.html`)
A protected AI conversation interface:
* Conversational sidebar with session creation, rename, search, and deletion.
* Dynamic Markdown rendering with syntax-highlighted code blocks and copy buttons.
* Long-term **Personal Memory Management** modal allowing users to inspect and delete memories the AI has automatically learned about them.
* Live backend connectivity indicator (🟢 Connected / 🔴 Offline instructions).

---

## 4. Backend Services & APIs

### 4.1 Cloudflare Worker (Auth & Core Services)
* **Runtime**: Cloudflare Workers (V8 Isolate runtime).
* **Router**: Hono Web Framework.
* **Database Driver**: Cloudflare D1 (`c.env.DB`).
* **Security Headers**: CORS enabled for client development and production domains.
* **Rate Limiting**: Built-in IP-based rate limiting on authentication routes (login, register, forgot-password).

### 4.2 Zabum AI Flask Backend (`zabum-backend/`)
* **Runtime**: Python 3.10+ / Flask / Flask-CORS.
* **Authentication**: Decoupled `@require_auth(permission="use_ai_assistant")` middleware.
* **LLM Engine**: Ollama local inference running `llama3.2`.
* **Database**: Local SQLite WAL database (`zabum-backend/storage/zabum.db`) maintaining user-isolated conversation tables and memories.
* **Memory Extraction**: Heuristic keyword & regex extraction engine that automatically captures facts stated by the user (e.g., *"Remember that I prefer TypeScript"*).

---

## 5. Role-Based Access Control (RBAC) Specification

### 5.1 Roles Matrix

| Role Name | Description | Default Assigned Permissions |
| :--- | :--- | :--- |
| **Admin** | Full system administrator with superuser capabilities | `users.read`, `users.create`, `users.update`, `users.delete`, `roles.manage`, `sessions.manage`, `use_ai_assistant` |
| **Moderator**| Content and user moderation capabilities | `users.read`, `users.update`, `use_ai_assistant` |
| **User** | Standard authenticated user | `users.read`, `use_ai_assistant` |

### 5.2 Permissions Matrix

| Permission Key | Resource | Action | Purpose |
| :--- | :--- | :--- | :--- |
| `users.read` | `users` | `read` | Allows user to read profile data and user listings |
| `users.create` | `users` | `create` | Allows creating new users directly via admin API |
| `users.update` | `users` | `update` | Allows updating user details and status |
| `users.delete` | `users` | `delete` | Allows removing user accounts |
| `roles.manage` | `roles` | `manage` | Allows assigning/revoking roles and modifying RBAC permissions |
| `sessions.manage`| `sessions`| `manage` | Allows inspecting and revoking active user sessions |
| `use_ai_assistant`| `ai` | `use` | Grants access to communicate with Zabum AI |

### 5.3 Authorization Enforcement Flow

```text
Client Request (with JWT)
        │
        ▼
Extract Bearer Token from Authorization Header
        │
        ├──> Token Missing / Invalid Format ─────────> Return HTTP 401 Unauthorized
        │
Validate Cryptographic Signature (HMAC-SHA256)
        │
        ├──> Signature Mismatch / Token Expired ──────> Return HTTP 401 Unauthorized
        │
Load User Profile, Roles, and Aggregated Permissions from D1
        │
Check Required Permission for Endpoint (e.g. use_ai_assistant)
        │
        ├──> Permission Missing in Claims ───────────> Return HTTP 403 Forbidden
        │
Attach Authenticated Context (user_id, email, roles, permissions)
        │
        ▼
Execute Route Handler with Verified user_id
```

---

## 6. Data Isolation & Security Model

### 6.1 User Isolation Rules
Every user-generated database entity must strictly enforce a foreign key relationship to the authenticated user ID:
1. **Never Trust Client Inputs**: Route handlers extract `user_id` strictly from the cryptographically verified JWT context (`authUser.id`). Request bodies or query parameters supplying `user_id` are completely ignored.
2. **Database Scoping**:
   * Cloudflare D1 tables (`jobs`, `favorites`, `user_settings`) filter with `WHERE user_id = ?`.
   * Zabum AI SQLite tables (`conversations`, `messages`, `memories`) filter with `WHERE user_id = ?`.
3. **Cross-Tenant Access Prevention**: If User B attempts to access `/jobs/:id` or `/api/conversations/:id` owned by User A, the query returns zero rows and responds with `HTTP 404 Not Found`.

### 6.2 Cryptography & Tokens
* **Password Hashing**: PBKDF2-SHA256 with 100,000 iterations and a unique 16-byte random salt per user.
* **Access Tokens (JWT)**:
  * Signed via HMAC-SHA256 using `JWT_SECRET`.
  * Claims include: `sub` (user_id), `email`, `roles`, `permissions`, `type: "access"`, `iat`, `exp` (15 minutes).
* **Refresh Tokens**:
  * 32-byte cryptographically secure random value encoded as a 64-character hex string.
  * Stored hashed in the `refresh_tokens` table with associated `session_id`, `user_id`, and 7-day expiration timestamp.

---

## 7. Database Schemas & Migrations

### 7.1 Cloudflare D1 Schema (SQLite)

#### Table: `users`
```sql
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    nickname TEXT,
    email_verified INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);
```

#### Table: `roles` & `permissions`
```sql
CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    description TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    assigned_by INTEGER,
    created_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);
```

#### Table: `sessions` & `refresh_tokens`
```sql
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    device_name TEXT,
    ip_address TEXT,
    user_agent TEXT,
    last_activity TEXT DEFAULT (datetime('now')),
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    session_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);
```

#### Table: `user_settings`, `jobs`, `favorites`
```sql
CREATE TABLE IF NOT EXISTS user_settings (
    user_id INTEGER PRIMARY KEY,
    theme TEXT DEFAULT 'dark',
    notifications_enabled INTEGER DEFAULT 1,
    dashboard_layout TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    company TEXT NOT NULL,
    role TEXT NOT NULL,
    status TEXT DEFAULT 'applied',
    salary_range TEXT,
    location TEXT,
    job_url TEXT,
    notes TEXT,
    applied_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS favorites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    item_type TEXT NOT NULL,
    item_id TEXT NOT NULL,
    item_title TEXT NOT NULL,
    item_metadata TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

### 7.2 Zabum AI SQLite Schema (`zabum-backend/storage/zabum.db`)

```sql
CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS memories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    category TEXT DEFAULT 'general',
    source TEXT DEFAULT 'chat',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```

---

## 8. API Endpoint Reference

### 8.1 Authentication Endpoints (Base: `/auth`)

#### `POST /auth/register`
* **Description**: Registers a new user account.
* **Body**: `{"email": "user@example.com", "password": "Password123!"}`
* **Response (201)**:
  ```json
  {
    "message": "Registration successful. Please check your email to verify your account.",
    "user": { "id": 4, "email": "user@example.com", "email_verified": false }
  }
  ```

#### `POST /auth/login`
* **Description**: Authenticates user and initiates an active session.
* **Body**: `{"email": "user@example.com", "password": "Password123!", "deviceName": "Chrome MacOS"}`
* **Response (200)**:
  ```json
  {
    "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
    "refreshToken": "4b6c3e9812...",
    "user": {
      "id": 4,
      "email": "user@example.com",
      "nickname": "Developer",
      "email_verified": true,
      "roles": ["User"],
      "permissions": ["users.read", "use_ai_assistant"]
    }
  }
  ```

#### `POST /auth/refresh`
* **Description**: Exchanges a valid refresh token for a new access token.
* **Body**: `{"refreshToken": "4b6c3e9812..."}`
* **Response (200)**: `{"accessToken": "eyJhbGci...", "refreshToken": "9a7f12..."}`

#### `GET /auth/verify`
* **Headers**: `Authorization: Bearer <accessToken>`
* **Description**: Validates token and returns verified identity with roles and permissions (used by Zabum AI).
* **Response (200)**:
  ```json
  {
    "valid": true,
    "user": {
      "id": 4,
      "email": "user@example.com",
      "nickname": "Developer",
      "roles": ["User"],
      "permissions": ["users.read", "use_ai_assistant"]
    }
  }
  ```

#### `POST /auth/logout`
* **Body**: `{"refreshToken": "4b6c3e9812..."}`
* **Description**: Revokes active session and associated refresh tokens.

---

### 8.2 User & Profile Endpoints

#### `GET /me`
* **Headers**: `Authorization: Bearer <accessToken>`
* **Description**: Returns current authenticated user profile, roles, and permissions.

#### `PUT /nickname`
* **Headers**: `Authorization: Bearer <accessToken>`
* **Body**: `{"nickname": "Swopnab"}`
* **Description**: Updates user display nickname (persisted in Cloudflare D1).

#### `POST /change-password`
* **Headers**: `Authorization: Bearer <accessToken>`
* **Body**: `{"currentPassword": "OldPassword123!", "newPassword": "NewPassword123!"}`

---

### 8.3 Session Management Endpoints

#### `GET /sessions`
* **Headers**: `Authorization: Bearer <accessToken>`
* **Description**: Retrieves all active sessions belonging to the user.

#### `DELETE /sessions/:id`
* **Headers**: `Authorization: Bearer <accessToken>`
* **Description**: Revokes a specific active session.

---

### 8.4 User Data Endpoints (Settings, Jobs, Favorites)

#### `GET /settings` & `PUT /settings`
* **Headers**: `Authorization: Bearer <accessToken>`
* **Description**: Manage user-isolated UI preferences and configurations.

#### `GET /jobs`, `POST /jobs`, `PUT /jobs/:id`, `DELETE /jobs/:id`
* **Headers**: `Authorization: Bearer <accessToken>`
* **Description**: Complete user-isolated CRUD for tracking job applications.

#### `GET /favorites`, `POST /favorites`, `DELETE /favorites/:id`
* **Headers**: `Authorization: Bearer <accessToken>`
* **Description**: Manage user-isolated saved items and bookmarks.

---

### 8.5 Zabum AI Endpoints (Base: `http://localhost:5001`)

#### `GET /api/status`
* **Description**: Public health check reporting Ollama availability and model status.

#### `POST /api/chat`
* **Headers**: `Authorization: Bearer <accessToken>`
* **Body**: `{"message": "Remember that I love Python", "conversation_id": 1}`
* **Response (200)**:
  ```json
  {
    "conversation_id": 1,
    "user_message": { "role": "user", "content": "Remember that I love Python" },
    "assistant_message": { "role": "assistant", "content": "I'll remember that you love Python!" },
    "memories_created": [{ "id": 1, "content": "user loves Python", "category": "preference" }]
  }
  ```

#### `GET /api/conversations`, `POST /api/conversations`, `DELETE /api/conversations/:id`
* **Headers**: `Authorization: Bearer <accessToken>`
* **Description**: Manage isolated chat conversation threads.

#### `GET /api/memories`, `DELETE /api/memories/:id`
* **Headers**: `Authorization: Bearer <accessToken>`
* **Description**: Inspect and delete long-term user memories.

---

## 9. Local Development & Deployment Guide

### 9.1 Prerequisites
* **Node.js**: v18.0.0 or higher (`node -v`)
* **Python**: v3.10 or higher (`python3 --version`)
* **Ollama**: (Optional for local AI) [https://ollama.com](https://ollama.com)

### 9.2 Initial Setup & Seeding

```bash
# 1. Clone repository
git clone https://github.com/Swopnab/JWT-auth-service-plus-RBAC.git
cd JWT-auth-service-plus-RBAC

# 2. Install Node dependencies
npm install

# 3. Apply database migrations to local Cloudflare D1
npm run db:migrate:local

# 4. Seed default roles, permissions, and test accounts
npm run db:seed:local

# 5. Install Python dependencies for Zabum AI
cd zabum-backend
pip install -r requirements.txt
cd ..
```

#### Default Test Accounts:
* **Admin**: `admin@example.com` / `Password123!`
* **Moderator**: `moderator@example.com` / `Password123!`
* **User**: `user@example.com` / `Password123!`

---

### 9.3 Running Local Servers

Run the development environment using npm workspace scripts:

```bash
# Terminal 1: Start Cloudflare Worker API (Port 8787)
npm run dev:api

# Terminal 2: Start Client Development Server (Port 5173)
npm run dev:client

# Terminal 3: Start Ollama (for AI features)
ollama serve
ollama pull llama3.2

# Terminal 4: Start Zabum AI Flask Backend (Port 5001)
cd zabum-backend
python3 app.py
```

---

### 9.4 Production Deployment

#### 1. Frontend (GitHub Pages)
The GitHub Pages deployment is automated via `.github/workflows/static.yml` on pushes to the `main` branch.
* Static deployment serves directly from repository root (`path: '.'`).
* Live URL: `https://swopnab.github.io/JWT-auth-service-plus-RBAC/`

#### 2. Backend (Cloudflare Worker & Production D1)
```bash
# Apply migrations to production Cloudflare D1
npm run db:migrate:prod

# Deploy Cloudflare Worker
npm run deploy:api
```

---

## 10. Troubleshooting & FAQ

#### Q1: Why does closing a tab require logging in again?
**Answer**: By design, authentication tokens are saved in `sessionStorage` (tab/window scoped) rather than persistent `localStorage` to maximize security and prevent unauthorized access on shared devices. Refreshing the same tab preserves authentication.

#### Q2: What happens if Ollama is not running?
**Answer**: The Zabum AI backend catches the offline connection and returns a clean, formatted guidance message (*"Zabum AI is offline. Start Ollama to use the assistant: 'ollama serve' and 'ollama pull llama3.2'"*) without crashing the application.

#### Q3: How do I change the Zabum AI Backend URL in production?
**Answer**: On `ai-assistant.html`, click the **⚙️ Backend** button in the header to configure a custom backend endpoint (saved in `localStorage.zabum_ai_api_url`).

---
*Documentation generated for SwopMobile Platform • Maintained by Swopnab.*

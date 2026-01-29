🔐 Test Login:

Email: test@test.com
Password: Password123!


# Auth Service with JWT and RBAC

A production-ready authentication and authorization service built with React, Cloudflare Workers, and D1. Features JWT-based authentication with refresh token rotation, comprehensive RBAC, audit logging, session management, and modern security best practices.

**Live Demo**: Coming soon (GitHub Pages + Cloudflare Workers)

## ✨ Features

### Core Authentication

- ✅ Email/password registration with email verification
- ✅ Login with JWT access tokens (15 min expiry)
- ✅ Refresh tokens with automatic rotation (7 day expiry)
- ✅ **Refresh token reuse detection** - Automatically revokes sessions on security breach
- ✅ Password reset flow with secure tokens
- ✅ Change password while authenticated
- ✅ Logout with session revocation

### Authorization (RBAC)

- ✅ Role-based access control with granular permissions
- ✅ Pre-defined roles: Admin, User, Moderator
- ✅ Route protection by permission
- ✅ Permission aggregation from multiple roles

### Session Management

- ✅ Multi-device support
- ✅ View all active sessions
- ✅ Revoke individual sessions
- ✅ Revoke all sessions (except current)
- ✅ Track device name, IP, user agent, last activity

### Security Features

- ✅ Password hashing with bcrypt (10 rounds)
- ✅ Rate limiting on sensitive endpoints (login, register, password reset)
- ✅ Input validation with Zod schemas
- ✅ CORS protection
- ✅ CSP headers
- ✅ No sensitive info in error messages
- ✅ localStorage for refresh tokens with clear documentation of tradeoffs

### Audit Logging

- ✅ Comprehensive event logging (register, login, logout, password changes, role changes)
- ✅ Stores actor user, target user, IP, user agent, timestamp, metadata
- ✅ Admin-only audit log viewer with filtering

### Differentiating Features

1. **Login History & Security Timeline** - Visual timeline of login attempts
2. **Authentication Analytics Dashboard** - DAU/WAU, login success rates, geographic distribution
3. **Security Score Gamification** - Calculate user security scores
4. **Trusted Dev ice Management** - Mark devices as trusted
5. **Flexible Rate Limiting** - Configurable per-endpoint limits

## 🏗️ Architecture

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────┐
│  GitHub Pages   │ ◄────► │ Cloudflare Worker│ ◄────► │ Cloudflare  │
│  (React + Vite) │  HTTPS  │   (Hono + JWT)   │   SQL   │  D1 (SQLite)│
└─────────────────┘         └──────────────────┘         └─────────────┘
```

### Tech Stack

**Frontend**:

- React 18
- Vite
- TypeScript
- Zustand (state management)
- React Router
- Axios (with interceptors)
- Lucide React (icons)

**Backend**:

- Cloudflare Workers
- Hono (web framework)
- TypeScript
- Jose (JWT)
- bcryptjs (password hashing)
- Zod (validation)

**Database**:

- Cloudflare D1 (SQLite)
- 11 tables (users, sessions, refresh_tokens, roles, permissions, audit_logs, etc.)

## 📊 Database Schema

```sql
- users (id, email, password_hash, email_verified, created_at, updated_at)
- sessions (id, user_id, device_name, ip_address, user_agent, last_activity, created_at)
- refresh_tokens (id, session_id, token_hash, expires_at, revoked_at)
- roles (id, name, description)
- permissions (id, name, resource, action, description)
- role_permissions (role_id, permission_id)
- user_roles (user_id, role_id, assigned_by)
- audit_logs (id, event_type, actor_user_id, target_user_id, ip, user_agent, metadata, created_at)
- password_reset_tokens (id, user_id, token_hash, expires_at, used_at)
- email_verification_tokens (id, user_id, token_hash, expires_at, used_at)
- trusted_devices (id, user_id, device_fingerprint, device_name, expires_at)
```

## 🚀 Setup Instructions

### Prerequisites

- Node.js 18+ and npm
- Cloudflare account (free tier works)
- Git

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/JWT-auth-service-plus-RBAC.git
cd JWT-auth-service-plus-RBAC
```

### 2. Setup Backend (Cloudflare Worker)

```bash
cd api
npm install

# Login to Cloudflare
npx wrangler login

# Create D1 database
npx wrangler d1 create auth-db

# Copy the database ID from output and update wrangler.toml
# Replace database_id = "" with the actual ID

# Run migrations
npx wrangler d1 execute auth-db --file=./migrations/0001_initial.sql

# Seed database with demo data
npx wrangler d1 execute auth-db --file=./seeds/dev-data.sql

# Run locally
npm run dev
# Worker will be available at http://localhost:8787
```

### 3. Setup Frontend (React + Vite)

```bash
cd ../client
npm install

# Create .env file
cp .env.example .env

# Update .env with your API URL
# For local dev: VITE_API_BASE_URL=http://localhost:8787
# For production: VITE_API_BASE_URL=https://your-worker.workers.dev

# Run locally
npm run dev
# Frontend will be available at http://localhost:5173
```

### 4. Demo Credentials

After seeding, you can log in with:

**Admin**:

- Email: `admin@example.com`
- Password: `Password123!`

**User**:

- Email: `user@example.com`
- Password: `Password123!`

**Moderator**:

- Email: `moderator@example.com`
- Password: `Password123!`

## 🌐 Deployment

### Deploy Backend to Cloudflare Workers

```bash
cd api

# Deploy
npm run deploy

# Note the deployed URL (e.g., https://auth-service-api.your-subdomain.workers.dev)
```

### Deploy Frontend to GitHub Pages

1. Update `client/vite.config.ts` base path to match your repo name
2. Update `client/.env` with production API URL
3. Push to GitHub
4. GitHub Actions will automatically deploy to Pages (workflow in `.github/workflows/deploy.yml`)

Or manually:

```bash
cd client
npm run build
npm run deploy
```

## 📝 API Documentation

### Authentication Endpoints

#### POST `/auth/register`

Register a new user account.

```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

Response (201):

```json
{
  "message": "Registration successful...",
  "user": { "id": 1, "email": "user@example.com" },
  "verificationLink": "http://localhost:5173/verify-email?token=..."
}
```

#### POST `/auth/login`

Authenticate user and receive tokens.

```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "deviceName": "Chrome on MacBook"
}
```

Response (200):

```json
{
  "accessToken": "eyJ...",
  "refreshToken": "abc123...",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "roles": ["User"],
    "permissions": ["users.read"]
  }
}
```

#### POST `/auth/refresh`

Exchange refresh token for new access + refresh tokens.

```json
{
  "refreshToken": "abc123..."
}
```

Response (200):

```json
{
  "accessToken": "eyJ...",
  "refreshToken": "xyz789..."
}
```

#### POST `/auth/logout`

Revoke refresh token and end session.

#### POST `/auth/forgot-password`

Request password reset token.

#### POST `/auth/reset-password`

Reset password with token.

#### POST `/auth/change-password` (Authenticated)

Change password while logged in.

#### POST `/auth/verify-email`

Verify email with token.

### User Endpoints (Authenticated)

#### GET `/me`

Get current user profile with roles and permissions.

#### GET `/sessions`

List all active sessions for current user.

#### DELETE `/sessions/:id`

Revoke a specific session.

#### DELETE `/sessions/revoke-all`

Revoke all sessions except current.

### Admin Endpoints (Requires Permissions)

#### GET `/admin/users` (requires `users.read`)

List all users with pagination.

#### GET `/admin/users/:id` (requires `users.read`)

Get user details with roles.

#### POST `/admin/users/:id/roles` (requires `roles.manage`)

Assign role to user.

#### GET `/admin/roles` (requires `roles.manage`)

List all roles.

#### GET `/admin/permissions` (requires `roles.manage`)

List all permissions.

#### GET `/admin/audit-logs` (requires `audit.read`)

View audit logs with filtering.

#### GET `/admin/analytics` (requires Admin role)

Get analytics dashboard data.

## 🔒 Security Best Practices

### Implemented

- ✅ Passwords hashed with bcrypt (10 rounds)
- ✅ JWT access tokens expire in 15 minutes
- ✅ Refresh tokens expire in 7 days
- ✅ Refresh token rotation on every use
- ✅ Refresh token reuse detection
- ✅ Rate limiting (5 login attempts per 5 min)
- ✅ Input validation on all endpoints
- ✅ CORS restricted to frontend origin
- ✅ CSP headers
- ✅ Audit logging on sensitive operations

### Token Storage Tradeoffs

**Refresh Token in localStorage:**

- ✅ Pros: Works with static hosting, persists across sessions
- ⚠️ Cons: Vulnerable to XSS attacks

**Mitigations:**

- Strict CSP headers
- All user input sanitized
- Short token lifetime (7 days)
- Token rotation
- Reuse detection

**Production Recommendations:**

- Consider using HttpOnly cookies if you can add a proxy server
- Implement additional XSS protections (sanitize all HTML)
- Monitor audit logs for suspicious activity

## 🧪 Testing

### Backend Unit Tests

```bash
cd api
npm test
```

### Test Scenarios

1. **Auth Flow**: Register → Verify Email → Login → Access Protected Route
2. **Token Refresh**: Wait for access token expiry → Make request → Auto-refresh
3. **Token Reuse Detection**: Use old refresh token → Session revoked
4. **RBAC**: Login as user → Try admin route → 403 Forbidden
5. **Multi-Session**: Login from 2 devices → Revoke one → Other still works
6. **Rate Limiting**: 6 login attempts in 1 minute → 429 Too Many Requests

## 📈 Future Enhancements

### High Priority

- [ ] Add frontend pages (Login, Register, Dashboard, Admin Panel)
- [ ] Implement Security Score calculation
- [ ] Add Login History timeline visualization
- [ ] Create Analytics dashboard charts
- [ ] Add email service integration (SendGrid/Mailgun)

### Medium Priority

- [ ] Two-factor authentication (TOTP)
- [ ] OAuth social logins (Google, GitHub)
- [ ] WebAuthn / Passkey support
- [ ] Device fingerprinting for anomaly detection
- [ ] Geolocation-based alerts

### Low Priority

- [ ] GraphQL API alternative
- [ ] Mobile app (React Native)
- [ ] Admin impersonation feature
- [ ] Webhook system for external integrations


## 🎓 Learning Resources

This project demonstrates:

- JWT authentication patterns
- Refresh token rotation
- RBAC implementation
- Audit logging
- Rate limiting
- Cloudflare Workers development
- React state management
- TypeScript best practices

## 📊 Project Stats

- **Lines of Code**: ~5,000+
- **Files**: 50+
- **API Endpoints**: 20+
- **Database Tables**: 11
- **Security Features**: 10+
- **Demo Users**: 3 (Admin, User, Moderator)



🔐 Demo User Credentials
According to the seed data (line 2):

Admin Account
Email: admin@example.com
Password: Password123!
Role: Admin (full access)
Other Test Accounts
Regular User:

Email: user@example.com
Password: Password123!
Role: User
Moderator:

Email: moderator@example.com
Password: Password123!
Role: Moderator

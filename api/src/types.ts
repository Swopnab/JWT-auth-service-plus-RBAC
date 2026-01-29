// TypeScript types for Auth Service

export interface User {
    id: number;
    email: string;
    password_hash: string;
    email_verified: number;
    created_at: string;
    updated_at: string;
}

export interface Session {
    id: string;
    user_id: number;
    device_name: string | null;
    ip_address: string | null;
    user_agent: string | null;
    last_activity: string;
    created_at: string;
}

export interface RefreshToken {
    id: number;
    session_id: string;
    token_hash: string;
    expires_at: string;
    created_at: string;
    revoked_at: string | null;
}

export interface Role {
    id: number;
    name: string;
    description: string | null;
    created_at: string;
}

export interface Permission {
    id: number;
    name: string;
    resource: string;
    action: string;
    description: string | null;
    created_at: string;
}

export interface AuditLog {
    id: number;
    event_type: string;
    actor_user_id: number | null;
    target_user_id: number | null;
    ip_address: string | null;
    user_agent: string | null;
    metadata: string | null;
    created_at: string;
}

export interface TrustedDevice {
    id: number;
    user_id: number;
    device_fingerprint: string;
    device_name: string | null;
    trusted_at: string;
    expires_at: string;
}

// API Response types
export interface UserWithRoles extends User {
    roles: Role[];
    permissions: Permission[];
}

export interface SessionWithUser extends Session {
    user: User;
}

// JWT Payload types
export interface AccessTokenPayload {
    sub: number; // user id
    email: string;
    roles: string[];
    permissions: string[];
    type: 'access';
}

export interface RefreshTokenPayload {
    sub: number; // user id
    sessionId: string;
    type: 'refresh';
}

// Request/Response types
export interface RegisterRequest {
    email: string;
    password: string;
}

export interface LoginRequest {
    email: string;
    password: string;
    deviceName?: string;
}

export interface LoginResponse {
    accessToken: string;
    refreshToken: string;
    user: UserWithRoles;
}

export interface RefreshRequest {
    refreshToken: string;
}

export interface ChangePasswordRequest {
    currentPassword: string;
    newPassword: string;
}

export interface ForgotPasswordRequest {
    email: string;
}

export interface ResetPasswordRequest {
    token: string;
    newPassword: string;
}

export interface VerifyEmailRequest {
    token: string;
}

// Cloudflare Worker environment bindings
export interface Env {
    DB: D1Database;
    JWT_ACCESS_SECRET: string;
    JWT_REFRESH_SECRET: string;
    ACCESS_TOKEN_EXPIRY: string;
    REFRESH_TOKEN_EXPIRY: string;
    FRONTEND_URL: string;
    RATE_LIMIT_LOGIN: string;
    RATE_LIMIT_WINDOW: string;
}

// Context type for authenticated requests
export interface AuthContext {
    user: UserWithRoles;
    sessionId: string;
}

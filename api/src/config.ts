// Configuration constants and helpers

export const config = {
    // Token expiry durations (in seconds for calculation)
    ACCESS_TOKEN_EXPIRY: 15 * 60, // 15 minutes
    REFRESH_TOKEN_EXPIRY: 7 * 24 * 60 * 60, // 7 days
    EMAIL_VERIFICATION_EXPIRY: 24 * 60 * 60, // 24 hours
    PASSWORD_RESET_EXPIRY: 60 * 60, // 1 hour
    TRUSTED_DEVICE_EXPIRY: 30 * 24 * 60 * 60, // 30 days

    // Security
    BCRYPT_ROUNDS: 10,
    MIN_PASSWORD_LENGTH: 8,

    // Rate limiting
    RATE_LIMIT_LOGIN_ATTEMPTS: 5,
    RATE_LIMIT_WINDOW: 5 * 60, // 5 minutes
    RATE_LIMIT_FORGOT_PASSWORD: 3,
    RATE_LIMIT_REGISTER: 10,

    // Pagination
    DEFAULT_PAGE_SIZE: 20,
    MAX_PAGE_SIZE: 100,
} as const;

// Helper to parse duration strings (e.g., "15m", "7d")
export function parseDuration(duration: string): number {
    const match = duration.match(/^(\d+)([smhd])$/);
    if (!match) {
        throw new Error(`Invalid duration format: ${duration}`);
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];

    const multipliers: Record<string, number> = {
        s: 1,
        m: 60,
        h: 60 * 60,
        d: 24 * 60 * 60,
    };

    return value * multipliers[unit];
}

// Helper to add seconds to current date
export function addSeconds(seconds: number): Date {
    return new Date(Date.now() + seconds * 1000);
}

// Helper to format date for D1 (SQLite uses ISO8601 strings)
export function formatDateForDB(date: Date): string {
    return date.toISOString().replace('T', ' ').replace('Z', '');
}

// Helper to check if token is expired
export function isExpired(expiresAt: string): boolean {
    return new Date(expiresAt) < new Date();
}

// Audit event types
export const AuditEventType = {
    REGISTER: 'register',
    LOGIN_SUCCESS: 'login_success',
    LOGIN_FAILED: 'login_failed',
    LOGOUT: 'logout',
    REFRESH_TOKEN: 'refresh_token',
    PASSWORD_RESET_REQUESTED: 'password_reset_requested',
    PASSWORD_RESET_COMPLETED: 'password_reset_completed',
    PASSWORD_CHANGED: 'password_changed',
    EMAIL_VERIFIED: 'email_verified',
    ROLE_ASSIGNED: 'role_assigned',
    ROLE_REMOVED: 'role_removed',
    SESSION_REVOKED: 'session_revoked',
    ALL_SESSIONS_REVOKED: 'all_sessions_revoked',
    DEVICE_TRUSTED: 'device_trusted',
    DEVICE_UNTRUSTED: 'device_untrusted',
} as const;

export type AuditEventType = typeof AuditEventType[keyof typeof AuditEventType];

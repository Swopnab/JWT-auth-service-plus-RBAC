// Cryptographic utilities

import * as crypto from 'crypto';

// Generate a secure random token
export function generateSecureToken(length: number = 32): string {
    const buffer = crypto.randomBytes(length);
    return buffer.toString('hex');
}

// Generate a random session ID
export function generateSessionId(): string {
    return generateSecureToken(16);
}

// Hash a token for storage (using SHA-256)
export function hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
}

// Generate device fingerprint from request headers
export function generateDeviceFingerprint(request: Request): string {
    const userAgent = request.headers.get('user-agent') || '';
    const acceptLanguage = request.headers.get('accept-language') || '';
    const acceptEncoding = request.headers.get('accept-encoding') || '';

    // Combine headers to create a fingerprint
    const fingerprintData = `${userAgent}|${acceptLanguage}|${acceptEncoding}`;

    return crypto.createHash('sha256').update(fingerprintData).digest('hex');
}

// Get IP address from request
export function getIpAddress(request: Request): string {
    // Cloudflare passes the real IP in CF-Connecting-IP header
    return request.headers.get('cf-connecting-ip') ||
        request.headers.get('x-forwarded-for')?.split(',')[0] ||
        'unknown';
}

// Get user agent from request
export function getUserAgent(request: Request): string {
    return request.headers.get('user-agent') || 'unknown';
}

// Verify password strength
export function isStrongPassword(password: string): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (password.length < 8) {
        errors.push('Password must be at least 8 characters long');
    }

    if (!/[a-z]/.test(password)) {
        errors.push('Password must contain at least one lowercase letter');
    }

    if (!/[A-Z]/.test(password)) {
        errors.push('Password must contain at least one uppercase letter');
    }

    if (!/[0-9]/.test(password)) {
        errors.push('Password must contain at least one number');
    }

    return {
        valid: errors.length === 0,
        errors,
    };
}

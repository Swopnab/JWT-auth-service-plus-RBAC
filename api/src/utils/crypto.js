// Cryptographic utilities using Web Crypto API (Cloudflare Workers compatible)  
// Vanilla JavaScript version

/**
 * Generate a secure random token
 * @param {number} [length=32] - Length of token in bytes
 * @returns {string} Hex string token
 */
export function generateSecureToken(length = 32) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate a random session ID
 * @returns {string} Session ID
 */
export function generateSessionId() {
    return generateSecureToken(16);
}

/**
 * Simple hash function for storing tokens
 * Note: This is a basic hash. In production, use subtle.digest in async handlers
 * @param {string} token - Token to hash
 * @returns {string} Hashed token
 */
export function hashToken(token) {
    let hash = 0;
    for (let i = 0; i < token.length; i++) {
        const char = token.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32bit integer
    }
    // Return as hex string
    return (hash >>> 0).toString(16).padStart(8, '0');
}

/**
 * Generate device fingerprint from request headers
 * @param {Request} request - HTTP request
 * @returns {string} Device fingerprint hash
 */
export function generateDeviceFingerprint(request) {
    const userAgent = request.headers.get('user-agent') || '';
    const acceptLanguage = request.headers.get('accept-language') || '';
    const acceptEncoding = request.headers.get('accept-encoding') || '';

    // Simple fingerprint - combine and hash
    const fingerprintData = `${userAgent}|${acceptLanguage}|${acceptEncoding}`;
    return hashToken(fingerprintData);
}

/**
 * Get IP address from request
 * @param {Request} request - HTTP request
 * @returns {string} IP address
 */
export function getIpAddress(request) {
    // Cloudflare passes the real IP in CF-Connecting-IP header
    return request.headers.get('cf-connecting-ip') ||
        request.headers.get('x-forwarded-for')?.split(',')[0] ||
        'unknown';
}

/**
 * Get user agent from request
 * @param {Request} request - HTTP request
 * @returns {string} User agent
 */
export function getUserAgent(request) {
    return request.headers.get('user-agent') || 'unknown';
}

/**
 * Verify password strength
 * @param {string} password - Password to validate
 * @returns {{valid: boolean, errors: string[]}} Validation result
 */
export function isStrongPassword(password) {
    const errors = [];

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

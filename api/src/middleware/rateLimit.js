// Rate limiting middleware - simple in-memory rate limiter
// Vanilla JavaScript version

import { RateLimitError } from '../utils/errors.js';

// In-memory store for rate limiting (resets on worker restart)
const rateLimitStore = new Map();

/**
 * Create rate limit middleware
 * @param {number} maxAttempts - Max attempts allowed
 * @param {number} windowSeconds - Time window in seconds
 * @returns {Function} Middleware function
 */
function createRateLimiter(maxAttempts, windowSeconds) {
    return async (c, next) => {
        const ip = c.req.header('cf-connecting-ip') ||
            c.req.header('x-forwarded-for')?.split(',')[0] ||
            'unknown';

        const key = `${c.req.path}:${ip}`;
        const now = Date.now();
        const windowMs = windowSeconds * 1000;

        // Get or create rate limit entry
        let entry = rateLimitStore.get(key);

        if (!entry || now - entry.resetTime > windowMs) {
            // Reset window
            entry = {
                count: 0,
                resetTime: now,
            };
        }

        entry.count++;
        rateLimitStore.set(key, entry);

        if (entry.count > maxAttempts) {
            throw new RateLimitError(`Too many requests. Please try again later.`);
        }

        // Clean up old entries periodically
        if (rateLimitStore.size > 10000) {
            for (const [k, v] of rateLimitStore.entries()) {
                if (now - v.resetTime > windowMs * 2) {
                    rateLimitStore.delete(k);
                }
            }
        }

        await next();
    };
}

// Export rate limiters for different endpoints
export const loginRateLimit = createRateLimiter(5, 300); // 5 attempts per 5 minutes
export const registerRateLimit = createRateLimiter(10, 3600); // 10 per hour
export const forgotPasswordRateLimit = createRateLimiter(3, 3600); // 3 per hour

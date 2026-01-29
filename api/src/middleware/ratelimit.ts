// Rate limiting middleware using in-memory cache
// Note: For production with multiple workers, consider using Cloudflare KV or Durable Objects

import type { Context, Next } from 'hono';
import type { Env } from '../types';
import { RateLimitError } from '../utils/errors';
import { getIpAddress } from '../utils/crypto';

interface RateLimitEntry {
    count: number;
    resetTime: number;
}

// Simple in-memory store (resets on worker restart)
const rateLimitStore = new Map<string, RateLimitEntry>();

// Cleanup old entries periodically
setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of rateLimitStore.entries()) {
        if (entry.resetTime < now) {
            rateLimitStore.delete(key);
        }
    }
}, 60000); // Clean up every minute

export function rateLimit(options: {
    maxRequests: number;
    windowSeconds: number;
    keyPrefix: string;
}) {
    return async (c: Context<{ Bindings: Env }>, next: Next) => {
        const ip = getIpAddress(c.req.raw);
        const key = `${options.keyPrefix}:${ip}`;
        const now = Date.now();

        let entry = rateLimitStore.get(key);

        if (!entry || entry.resetTime < now) {
            // Create new entry
            entry = {
                count: 1,
                resetTime: now + (options.windowSeconds * 1000),
            };
            rateLimitStore.set(key, entry);
        } else {
            // Increment existing entry
            entry.count++;

            if (entry.count > options.maxRequests) {
                const retryAfter = Math.ceil((entry.resetTime - now) / 1000);
                c.header('Retry-After', retryAfter.toString());
                throw new RateLimitError(
                    `Rate limit exceeded. Try again in ${retryAfter} seconds.`
                );
            }
        }

        // Add rate limit headers
        c.header('X-RateLimit-Limit', options.maxRequests.toString());
        c.header('X-RateLimit-Remaining', (options.maxRequests - entry.count).toString());
        c.header('X-RateLimit-Reset', new Date(entry.resetTime).toISOString());

        await next();
    };
}

// Predefined rate limiters
export const loginRateLimit = rateLimit({
    maxRequests: 5,
    windowSeconds: 300, // 5 minutes
    keyPrefix: 'login',
});

export const registerRateLimit = rateLimit({
    maxRequests: 10,
    windowSeconds: 3600, // 1 hour
    keyPrefix: 'register',
});

export const forgotPasswordRateLimit = rateLimit({
    maxRequests: 3,
    windowSeconds: 3600, // 1 hour
    keyPrefix: 'forgot-password',
});

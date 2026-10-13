// Persistent fixed-window limits shared by all Workers using the same D1 database.
import { RateLimitError } from '../utils/errors.js';
import { hashToken } from '../utils/crypto.js';

export function createRateLimiter(maxAttempts, windowSeconds) {
    return async (c, next) => {
        // Cloudflare overwrites this header. Do not trust X-Forwarded-For.
        const ip = c.req.header('cf-connecting-ip') || 'local';
        const now = Math.floor(Date.now() / 1000);
        const bucket = Math.floor(now / windowSeconds);
        const expiresAt = (bucket + 1) * windowSeconds;
        const key = await hashToken(`${c.req.path}:${ip}:${bucket}`);
        const entry = await c.env.DB.prepare(
            `INSERT INTO rate_limits (key, count, expires_at) VALUES (?, 1, ?)
             ON CONFLICT(key) DO UPDATE SET count = count + 1 RETURNING count`
        ).bind(key, expiresAt).first();
        await c.env.DB.prepare('DELETE FROM rate_limits WHERE expires_at <= ?').bind(now).run();
        c.header('X-RateLimit-Limit', String(maxAttempts));
        c.header('X-RateLimit-Remaining', String(Math.max(0, maxAttempts - entry.count)));
        if (entry.count > maxAttempts) {
            c.header('Retry-After', String(expiresAt - now));
            throw new RateLimitError('Too many requests. Please try again later.');
        }
        await next();
    };
}
export const loginRateLimit = createRateLimiter(5, 300);
export const registerRateLimit = createRateLimiter(10, 3600);
export const forgotPasswordRateLimit = createRateLimiter(3, 3600);

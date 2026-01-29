// Authentication middleware - verifies JWT and loads user context
// Vanilla JavaScript version

import { AuthService } from '../services/auth.service.js';
import { UserService } from '../services/user.service.js';
import { UnauthorizedError } from '../utils/errors.js';

/**
 * Middleware to verify JWT and load user context
 * @param {Object} c - Hono context
 * @param {Function} next - Next middleware
 * @returns {Promise<void>}
 */
export async function authMiddleware(c, next) {
    const authHeader = c.req.header('Authorization');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new UnauthorizedError('Missing or invalid authorization header');
    }

    const token = authHeader.substring(7);

    const authService = new AuthService(c.env, c.env.DB);
    const userService = new UserService(c.env.DB);

    try {
        const payload = await authService.verifyAccessToken(token);
        const user = await userService.getUserWithRoles(payload.sub);

        if (!user) {
            throw new UnauthorizedError('User not found');
        }

        // Store user context
        c.set('authContext', {
            user,
            sessionId: '', // Will be set by routes that need it
        });

        await next();
    } catch (error) {
        if (error instanceof UnauthorizedError) {
            throw error;
        }
        throw new UnauthorizedError('Invalid access token');
    }
}

/**
 * Helper to get auth context from request
 * @param {Object} c - Hono context
 * @returns {Object} Auth context with user and sessionId
 */
export function getAuthContext(c) {
    const context = c.get('authContext');
    if (!context) {
        throw new UnauthorizedError('Not authenticated');
    }
    return context;
}

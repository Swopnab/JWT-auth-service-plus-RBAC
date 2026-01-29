// Authentication middleware - verifies JWT and loads user context

import type { Context, Next } from 'hono';
import type { Env, AuthContext } from '../types';
import { AuthService } from '../services/auth.service';
import { UserService } from '../services/user.service';
import { UnauthorizedError } from '../utils/errors';

export async function authMiddleware(c: Context<{ Bindings: Env }>, next: Next) {
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
        } as AuthContext);

        await next();
    } catch (error) {
        if (error instanceof UnauthorizedError) {
            throw error;
        }
        throw new UnauthorizedError('Invalid access token');
    }
}

// Helper to get auth context from request
export function getAuthContext(c: Context): AuthContext {
    const context = c.get('authContext');
    if (!context) {
        throw new UnauthorizedError('Not authenticated');
    }
    return context;
}

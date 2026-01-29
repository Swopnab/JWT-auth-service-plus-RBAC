// RBAC middleware - checks user permissions

import type { Context, Next } from 'hono';
import { getAuthContext } from './auth';
import { ForbiddenError } from '../utils/errors';

// Middleware factory to require specific permission
export function requirePermission(permissionName: string) {
    return async (c: Context, next: Next) => {
        const { user } = getAuthContext(c);

        const hasPermission = user.permissions.some(p => p.name === permissionName);

        if (!hasPermission) {
            throw new ForbiddenError(`Missing required permission: ${permissionName}`);
        }

        await next();
    };
}

// Middleware factory to require specific role
export function requireRole(roleName: string) {
    return async (c: Context, next: Next) => {
        const { user } = getAuthContext(c);

        const hasRole = user.roles.some(r => r.name === roleName);

        if (!hasRole) {
            throw new ForbiddenError(`Missing required role: ${roleName}`);
        }

        await next();
    };
}

// Middleware to require any of the specified permissions
export function requireAnyPermission(...permissionNames: string[]) {
    return async (c: Context, next: Next) => {
        const { user } = getAuthContext(c);

        const hasAnyPermission = user.permissions.some(p =>
            permissionNames.includes(p.name)
        );

        if (!hasAnyPermission) {
            throw new ForbiddenError(
                `Missing required permissions. Need one of: ${permissionNames.join(', ')}`
            );
        }

        await next();
    };
}

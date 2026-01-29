// Admin routes (Vanilla JavaScript - Placeholder for now)

import { Hono } from 'hono';
import { authMiddleware, getAuthContext } from '../middleware/auth.js';
import { UserService } from '../services/user.service.js';
import { ForbiddenError } from '../utils/errors.js';

const admin = new Hono();

// Middleware to check admin role
async function requireAdmin(c, next) {
    const { user } = getAuthContext(c);

    const isAdmin = user.roles.some(role => role.name === 'Admin');

    if (!isAdmin) {
        throw new ForbiddenError('Admin access required');
    }

    await next();
}

// GET /admin/users - List all users (admin only)
admin.get('/users', authMiddleware, requireAdmin, async (c) => {
    const userService = new UserService(c.env.DB);

    const page = parseInt(c.req.query('page') || '1');
    const limit = parseInt(c.req.query('limit') || '20');

    const users = await userService.getAllUsers(page, limit);
    const total = await userService.getUserCount();

    return c.json({
        users: users.map(u => ({
            id: u.id,
            email: u.email,
            email_verified: u.email_verified === 1,
            created_at: u.created_at,
        })),
        pagination: {
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit),
        },
    });
});

// GET /admin/users/:id - Get user details (admin only)
admin.get('/users/:id', authMiddleware, requireAdmin, async (c) => {
    const userId = parseInt(c.req.param('id'));
    const userService = new UserService(c.env.DB);

    const user = await userService.getUserWithRoles(userId);

    if (!user) {
        return c.json({ error: 'User not found' }, 404);
    }

    return c.json({
        id: user.id,
        email: user.email,
        email_verified: user.email_verified === 1,
        roles: user.roles,
        permissions: user.permissions,
        created_at: user.created_at,
    });
});

export default admin;

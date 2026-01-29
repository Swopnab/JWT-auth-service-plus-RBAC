// Admin routes for user and role management

import { Hono } from 'hono';
import type { Env } from '../types';
import { UserService } from '../services/user.service';
import { AuditService } from '../services/audit.service';
import { authMiddleware, getAuthContext } from '../middleware/auth';
import { requirePermission, requireRole } from '../middleware/rbac';
import { paginationSchema } from '../utils/validation';
import { getIpAddress, getUserAgent } from '../utils/crypto';
import { AuditEventType } from '../config';

const admin = new Hono<{ Bindings: Env }>();

// All routes require authentication
admin.use('/*', authMiddleware);

// GET /admin/users - List all users (requires users.read permission)
admin.get('/users', requirePermission('users.read'), async (c) => {
    const userService = new UserService(c.env.DB);

    const { page, limit } = paginationSchema.parse({
        page: c.req.query('page'),
        limit: c.req.query('limit'),
    });

    const users = await userService.getAllUsers(page, limit);
    const total = await userService.getUserCount();

    return c.json({
        users: users.map(u => ({
            id: u.id,
            email: u.email,
            email_verified: u.email_verified,
            created_at: u.created_at,
        })),
        pagination: {
            page,
            limit,
            total,
            pages: Math.ceil(total / limit),
        },
    });
});

// GET /admin/users/:id - Get user details with roles
admin.get('/users/:id', requirePermission('users.read'), async (c) => {
    const userId = parseInt(c.req.param('id'));
    const userService = new UserService(c.env.DB);

    const user = await userService.getUserWithRoles(userId);
    if (!user) {
        return c.json({ error: 'User not found' }, 404);
    }

    return c.json({
        id: user.id,
        email: user.email,
        email_verified: user.email_verified,
        created_at: user.created_at,
        roles: user.roles.map(r => ({ id: r.id, name: r.name })),
        permissions: user.permissions.map(p => ({ id: p.id, name: p.name })),
    });
});

// POST /admin/users/:id/roles - Assign role to user
admin.post('/users/:id/roles', requirePermission('roles.manage'), async (c) => {
    const userId = parseInt(c.req.param('id'));
    const { roleId } = await c.req.json();

    const auth = getAuthContext(c);
    const userService = new UserService(c.env.DB);
    const auditService = new AuditService(c.env.DB);

    await userService.assignRole(userId, roleId, auth.user.id);

    // Log role assignment
    await auditService.logEvent(
        AuditEventType.ROLE_ASSIGNED,
        auth.user.id,
        userId,
        getIpAddress(c.req.raw),
        getUserAgent(c.req.raw),
        { roleId }
    );

    return c.json({ message: 'Role assigned successfully' });
});

// DELETE /admin/users/:id/roles/:roleId - Remove role from user
admin.delete('/users/:id/roles/:roleId', requirePermission('roles.manage'), async (c) => {
    const userId = parseInt(c.req.param('id'));
    const roleId = parseInt(c.req.param('roleId'));

    const auth = getAuthContext(c);
    const userService = new UserService(c.env.DB);
    const auditService = new AuditService(c.env.DB);

    await userService.removeRole(userId, roleId);

    // Log role removal
    await auditService.logEvent(
        AuditEventType.ROLE_REMOVED,
        auth.user.id,
        userId,
        getIpAddress(c.req.raw),
        getUserAgent(c.req.raw),
        { roleId }
    );

    return c.json({ message: 'Role removed successfully' });
});

// GET /admin/roles - List all roles
admin.get('/roles', requirePermission('roles.manage'), async (c) => {
    const result = await c.env.DB
        .prepare('SELECT * FROM roles ORDER BY name')
        .all();

    return c.json({ roles: result.results || [] });
});

// GET /admin/permissions - List all permissions
admin.get('/permissions', requirePermission('roles.manage'), async (c) => {
    const result = await c.env.DB
        .prepare('SELECT * FROM permissions ORDER BY resource, action')
        .all();

    return c.json({ permissions: result.results || [] });
});

// GET /admin/audit-logs - View audit logs
admin.get('/audit-logs', requirePermission('audit.read'), async (c) => {
    const auditService = new AuditService(c.env.DB);

    const { page, limit } = paginationSchema.parse({
        page: c.req.query('page'),
        limit: c.req.query('limit'),
    });

    const eventType = c.req.query('eventType');
    const userId = c.req.query('userId') ? parseInt(c.req.query('userId')!) : undefined;

    const logs = await auditService.getLogs({
        eventType,
        userId,
        page,
        limit,
    });

    const total = await auditService.getLogCount({ eventType, userId });

    return c.json({
        logs,
        pagination: {
            page,
            limit,
            total,
            pages: Math.ceil(total / limit),
        },
    });
});

// GET /admin/analytics - Analytics dashboard data
admin.get('/analytics', requireRole('Admin'), async (c) => {
    const db = c.env.DB;

    // Get total users
    const totalUsers = await db
        .prepare('SELECT COUNT(*) as count FROM users')
        .first<{ count: number }>();

    // Get email verification rate
    const verifiedUsers = await db
        .prepare('SELECT COUNT(*) as count FROM users WHERE email_verified = 1')
        .first<{ count: number }>();

    // Get login stats (last 30 days)
    const loginStats = await db
        .prepare(`
      SELECT 
        COUNT(*) as total_logins,
        SUM(CASE WHEN event_type = 'login_success' THEN 1 ELSE 0 END) as successful_logins,
        SUM(CASE WHEN event_type = 'login_failed' THEN 1 ELSE 0 END) as failed_logins
      FROM audit_logs
      WHERE event_type IN ('login_success', 'login_failed')
        AND created_at >= datetime('now', '-30 days')
    `)
        .first<{ total_logins: number; successful_logins: number; failed_logins: number }>();

    // Get active sessions
    const activeSessions = await db
        .prepare('SELECT COUNT(*) as count FROM sessions')
        .first<{ count: number }>();

    return c.json({
        users: {
            total: totalUsers?.count || 0,
            verified: verifiedUsers?.count || 0,
            verificationRate: totalUsers?.count
                ? ((verifiedUsers?.count || 0) / totalUsers.count * 100).toFixed(2)
                : 0,
        },
        logins: {
            total: loginStats?.total_logins || 0,
            successful: loginStats?.successful_logins || 0,
            failed: loginStats?.failed_logins || 0,
            successRate: loginStats?.total_logins
                ? ((loginStats.successful_logins / loginStats.total_logins) * 100).toFixed(2)
                : 0,
        },
        sessions: {
            active: activeSessions?.count || 0,
        },
    });
});

export default admin;

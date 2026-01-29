// User routes (Vanilla JavaScript)

import { Hono } from 'hono';
import { authMiddleware, getAuthContext } from '../middleware/auth.js';
import { UserService } from '../services/user.service.js';
import { AuthService } from '../services/auth.service.js';
import { isStrongPassword, hashToken } from '../utils/crypto.js';
import { ValidationError } from '../utils/errors.js';

const user = new Hono();

// GET /me - Get current user profile
user.get('/me', authMiddleware, async (c) => {
    const { user } = getAuthContext(c);

    return c.json({
        id: user.id,
        email: user.email,
        email_verified: user.email_verified === 1,
        roles: user.roles,
        permissions: user.permissions,
        created_at: user.created_at,
    });
});

// GET /sessions - Get all active sessions
user.get('/sessions', authMiddleware, async (c) => {
    const { user } = getAuthContext(c);

    const sessions = await c.env.DB
        .prepare(
            `SELECT id, device_name, ip_address, user_agent, last_activity, created_at 
       FROM sessions 
       WHERE user_id = ? 
       ORDER BY last_activity DESC`
        )
        .bind(user.id)
        .all();

    return c.json({ sessions: sessions.results || [] });
});

// DELETE /sessions/:id - Revoke a specific session
user.delete('/sessions/:id', authMiddleware, async (c) => {
    const { user } = getAuthContext(c);
    const sessionId = c.req.param('id');

    const authService = new AuthService(c.env, c.env.DB);

    // Verify session belongs to user
    const session = await c.env.DB
        .prepare('SELECT user_id FROM sessions WHERE id = ?')
        .bind(sessionId)
        .first();

    if (!session || session.user_id !== user.id) {
        return c.json({ error: 'Session not found' }, 404);
    }

    await authService.revokeSession(sessionId);

    return c.json({ message: 'Session revoked successfully' });
});

// POST /change-password - Change user password
user.post('/change-password', authMiddleware, async (c) => {
    const { user } = getAuthContext(c);
    const body = await c.req.json();
    const { currentPassword, newPassword } = body;

    if (!currentPassword || !newPassword) {
        throw new ValidationError('Current password and new password are required');
    }

    // Password strength check
    const { valid, errors } = isStrongPassword(newPassword);
    if (!valid) {
        throw new ValidationError('Password is too weak', { password: errors });
    }

    const userService = new UserService(c.env.DB);
    const authService = new AuthService(c.env, c.env.DB);

    // Get full user record
    const fullUser = await userService.getUserById(user.id);

    // Verify current password
    const isValid = await authService.verifyPassword(currentPassword, fullUser.password_hash);
    if (!isValid) {
        throw new ValidationError('Current password is incorrect');
    }

    // Update password
    const newPasswordHash = await authService.hashPassword(newPassword);
    await userService.updatePassword(user.id, newPasswordHash);

    // Optionally revoke all other sessions for security
    // await authService.revokeAllSessions(user.id);

    return c.json({ message: 'Password changed successfully' });
});

export default user;

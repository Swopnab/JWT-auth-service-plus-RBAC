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
        nickname: user.nickname || null,
        email_verified: user.email_verified === 1,
        roles: user.roles,
        permissions: user.permissions,
        created_at: user.created_at,
    });
});

// PUT /nickname or PATCH /nickname - Update user nickname
async function handleUpdateNickname(c) {
    const { user: authUser } = getAuthContext(c);
    const body = await c.req.json().catch(() => ({}));
    let { nickname } = body;

    if (nickname !== null && nickname !== undefined) {
        nickname = String(nickname).trim();
        if (nickname.length > 0 && (nickname.length < 2 || nickname.length > 50)) {
            throw new ValidationError('Nickname must be between 2 and 50 characters');
        }
        if (nickname.length === 0) {
            nickname = null;
        }
    } else {
        nickname = null;
    }

    const userService = new UserService(c.env.DB);
    await userService.updateNickname(authUser.id, nickname);

    const updatedUser = await userService.getUserById(authUser.id);

    return c.json({
        message: 'Nickname updated successfully',
        user: {
            id: updatedUser.id,
            email: updatedUser.email,
            nickname: updatedUser.nickname || null,
            email_verified: updatedUser.email_verified === 1
        }
    });
}

user.put('/nickname', authMiddleware, handleUpdateNickname);
user.patch('/nickname', authMiddleware, handleUpdateNickname);
user.put('/profile', authMiddleware, handleUpdateNickname);

// GET /sessions - Get all active sessions for authenticated user
user.get('/sessions', authMiddleware, async (c) => {
    const { user: authUser } = getAuthContext(c);

    const sessions = await c.env.DB
        .prepare(
            `SELECT id, device_name, ip_address, user_agent, last_activity, created_at 
       FROM sessions 
       WHERE user_id = ? 
       ORDER BY last_activity DESC`
        )
        .bind(authUser.id)
        .all();

    return c.json({ sessions: sessions.results || [] });
});

// DELETE /sessions/:id - Revoke a specific session
user.delete('/sessions/:id', authMiddleware, async (c) => {
    const { user: authUser } = getAuthContext(c);
    const sessionId = c.req.param('id');

    const authService = new AuthService(c.env, c.env.DB);

    // Verify session belongs to user
    const session = await c.env.DB
        .prepare('SELECT user_id FROM sessions WHERE id = ?')
        .bind(sessionId)
        .first();

    if (!session || session.user_id !== authUser.id) {
        return c.json({ error: 'Session not found' }, 404);
    }

    await authService.revokeSession(sessionId);

    return c.json({ message: 'Session revoked successfully' });
});

// GET /settings - Get user settings
user.get('/settings', authMiddleware, async (c) => {
    const { user: authUser } = getAuthContext(c);

    let settings = await c.env.DB
        .prepare('SELECT * FROM user_settings WHERE user_id = ?')
        .bind(authUser.id)
        .first();

    if (!settings) {
        // Return default settings
        settings = {
            user_id: authUser.id,
            theme: 'dark',
            notifications_enabled: 1,
            dashboard_layout: null
        };
    }

    return c.json({ settings });
});

// PUT /settings - Update user settings
user.put('/settings', authMiddleware, async (c) => {
    const { user: authUser } = getAuthContext(c);
    const body = await c.req.json();
    const { theme, notifications_enabled, dashboard_layout } = body;

    const currentTheme = theme || 'dark';
    const notifications = notifications_enabled !== undefined ? (notifications_enabled ? 1 : 0) : 1;
    const layout = dashboard_layout ? JSON.stringify(dashboard_layout) : null;

    await c.env.DB
        .prepare(
            `INSERT INTO user_settings (user_id, theme, notifications_enabled, dashboard_layout, created_at, updated_at)
             VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))
             ON CONFLICT(user_id) DO UPDATE SET
               theme = excluded.theme,
               notifications_enabled = excluded.notifications_enabled,
               dashboard_layout = excluded.dashboard_layout,
               updated_at = datetime('now')`
        )
        .bind(authUser.id, currentTheme, notifications, layout)
        .run();

    const updated = await c.env.DB
        .prepare('SELECT * FROM user_settings WHERE user_id = ?')
        .bind(authUser.id)
        .first();

    return c.json({ message: 'Settings updated successfully', settings: updated });
});

// POST /change-password - Change user password
user.post('/change-password', authMiddleware, async (c) => {
    const { user: authUser } = getAuthContext(c);
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
    const fullUser = await userService.getUserById(authUser.id);

    // Verify current password
    const isValid = await authService.verifyPassword(currentPassword, fullUser.password_hash);
    if (!isValid) {
        throw new ValidationError('Current password is incorrect');
    }

    // Update password
    const newPasswordHash = await authService.hashPassword(newPassword);
    await userService.updatePassword(authUser.id, newPasswordHash);

    return c.json({ message: 'Password changed successfully' });
});

export default user;

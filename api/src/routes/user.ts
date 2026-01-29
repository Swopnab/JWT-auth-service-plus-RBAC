// User routes (profile and session management)

import { Hono } from 'hono';
import type { Env } from '../types';
import { UserService } from '../services/user.service';
import { SessionService } from '../services/session.service';
import { AuthService } from '../services/auth.service';
import { AuditService } from '../services/audit.service';
import { authMiddleware, getAuthContext } from '../middleware/auth';
import { AuditEventType } from '../config';
import { getIpAddress, getUserAgent } from '../utils/crypto';
import { NotFoundError, ForbiddenError } from '../utils/errors';

const user = new Hono<{ Bindings: Env }>();

// All routes require authentication
user.use('/*', authMiddleware);

// GET /me - Get current user info
user.get('/me', async (c) => {
    const auth = getAuthContext(c);

    return c.json({
        id: auth.user.id,
        email: auth.user.email,
        email_verified: auth.user.email_verified,
        roles: auth.user.roles.map(r => ({ id: r.id, name: r.name })),
        permissions: auth.user.permissions.map(p => ({ id: p.id, name: p.name })),
        created_at: auth.user.created_at,
    });
});

// GET /sessions - Get all active sessions for current user
user.get('/sessions', async (c) => {
    const auth = getAuthContext(c);
    const sessionService = new SessionService(c.env.DB);

    const sessions = await sessionService.getUserSessions(auth.user.id);

    return c.json({ sessions });
});

// DELETE /sessions/:id - Revoke a specific session
user.delete('/sessions/:id', async (c) => {
    const sessionId = c.req.param('id');
    const auth = getAuthContext(c);

    const sessionService = new SessionService(c.env.DB);
    const authService = new AuthService(c.env, c.env.DB);
    const auditService = new AuditService(c.env.DB);

    // Verify user owns this session
    const isOwner = await sessionService.verifySessionOwnership(sessionId, auth.user.id);
    if (!isOwner) {
        throw new ForbiddenError('You can only revoke your own sessions');
    }

    // Revoke the session
    await authService.revokeSession(sessionId);

    // Log session revocation
    await auditService.logEvent(
        AuditEventType.SESSION_REVOKED,
        auth.user.id,
        null,
        getIpAddress(c.req.raw),
        getUserAgent(c.req.raw),
        { revokedSessionId: sessionId }
    );

    return c.json({ message: 'Session revoked successfully' });
});

// DELETE /sessions/revoke-all - Revoke all sessions except current
user.delete('/sessions/revoke-all', async (c) => {
    const auth = getAuthContext(c);
    const authService = new AuthService(c.env, c.env.DB);
    const auditService = new AuditService(c.env.DB);

    // Get current session ID from refresh token (if provided)
    const body = await c.req.json().catch(() => ({}));
    const currentSessionId = body.currentSessionId || null;

    // Revoke all sessions
    await authService.revokeAllSessions(auth.user.id, currentSessionId);

    // Log all sessions revocation
    await auditService.logEvent(
        AuditEventType.ALL_SESSIONS_REVOKED,
        auth.user.id,
        null,
        getIpAddress(c.req.raw),
        getUserAgent(c.req.raw)
    );

    return c.json({ message: 'All sessions revoked successfully' });
});

export default user;

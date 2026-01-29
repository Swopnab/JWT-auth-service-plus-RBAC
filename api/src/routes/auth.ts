// Authentication routes

import { Hono } from 'hono';
import type { Env } from '../types';
import { AuthService } from '../services/auth.service';
import { UserService } from '../services/user.service';
import { SessionService } from '../services/session.service';
import { AuditService } from '../services/audit.service';
import {
    registerSchema,
    loginSchema,
    refreshTokenSchema,
    changePasswordSchema,
    forgotPasswordSchema,
    resetPasswordSchema,
    verifyEmailSchema,
    validateBody,
} from '../utils/validation';
import { getIpAddress, getUserAgent, hashToken } from '../utils/crypto';
import { AuditEventType } from '../config';
import {
    generateVerificationEmail,
    generatePasswordResetEmail,
    sendEmailDev,
} from '../utils/emails';
import { authMiddleware } from '../middleware/auth';
import { auditLog } from '../middleware/audit';
import {
    loginRate Limit,
    registerRateLimit,
    forgotPasswordRateLimit,
} from '../middleware/ratelimit';
import { UnauthorizedError, NotFoundError, ConflictError } from '../utils/errors';

const auth = new Hono<{ Bindings: Env }>();

// POST /auth/register
auth.post('/register', registerRateLimit, async (c) => {
    const { email, password } = await validateBody(c.req.raw, registerSchema);

    const userService = new UserService(c.env.DB);
    const authService = new AuthService(c.env, c.env.DB);
    const auditService = new AuditService(c.env.DB);

    // Check if user already exists
    const existingUser = await userService.getUserByEmail(email);
    if (existingUser) {
        throw new ConflictError('User with this email already exists');
    }

    // Hash password and create user
    const passwordHash = await authService.hashPassword(password);
    const user = await userService.createUser(email, passwordHash);

    // Generate verification token
    const verificationToken = await authService.generateEmailVerificationToken(user.id);

    // Send verification email (dev mode)
    const emailTemplate = generateVerificationEmail(
        email,
        verificationToken,
        c.env.FRONTEND_URL
    );
    const emailResult = sendEmailDev(emailTemplate);

    // Log audit event
    await auditService.logEvent(
        AuditEventType.REGISTER,
        user.id,
        null,
        getIpAddress(c.req.raw),
        getUserAgent(c.req.raw)
    );

    return c.json({
        message: 'Registration successful. Please check your email to verify your account.',
        user: {
            id: user.id,
            email: user.email,
            email_verified: false,
        },
        // In dev mode, return the verification link
        ...(emailResult.link ? { verificationLink: emailResult.link } : {}),
    }, 201);
});

// POST /auth/verify-email
auth.post('/verify-email', async (c) => {
    const { token } = await validateBody(c.req.raw, verifyEmailSchema);

    const userService = new UserService(c.env.DB);
    const auditService = new AuditService(c.env.DB);
    const tokenHash = hashToken(token);

    // Find the verification token
    const result = await c.env.DB
        .prepare(
            `SELECT * FROM email_verification_tokens 
       WHERE token_hash = ? AND used_at IS NULL`
        )
        .bind(tokenHash)
        .first<{ user_id: number; expires_at: string }>();

    if (!result) {
        throw new UnauthorizedError('Invalid or already used verification token');
    }

    // Check if expired
    if (new Date(result.expires_at) < new Date()) {
        throw new UnauthorizedError('Verification token has expired');
    }

    // Mark email as verified
    await userService.markEmailVerified(result.user_id);

    // Mark token as used
    await c.env.DB
        .prepare('UPDATE email_verification_tokens SET used_at = datetime(\'now\') WHERE token_hash = ?')
        .bind(tokenHash)
        .run();

    // Log audit event
    await auditService.logEvent(
        AuditEventType.EMAIL_VERIFIED,
        result.user_id,
        null,
        getIpAddress(c.req.raw),
        getUserAgent(c.req.raw)
    );

    return c.json({ message: 'Email verified successfully' });
});

// POST /auth/login
auth.post('/login', loginRateLimit, async (c) => {
    const { email, password, deviceName } = await validateBody(c.req.raw, loginSchema);

    const userService = new UserService(c.env.DB);
    const authService = new AuthService(c.env, c.env.DB);
    const sessionService = new SessionService(c.env.DB);
    const auditService = new AuditService(c.env.DB);

    // Find user
    const user = await userService.getUserByEmail(email);
    if (!user) {
        // Log failed login
        await auditService.logEvent(
            AuditEventType.LOGIN_FAILED,
            null,
            null,
            getIpAddress(c.req.raw),
            getUserAgent(c.req.raw),
            { email, reason: 'User not found' }
        );
        throw new UnauthorizedError('Invalid email or password');
    }

    // Verify password
    const isValidPassword = await authService.verifyPassword(password, user.password_hash);
    if (!isValidPassword) {
        // Log failed login
        await auditService.logEvent(
            AuditEventType.LOGIN_FAILED,
            user.id,
            null,
            getIpAddress(c.req.raw),
            getUserAgent(c.req.raw),
            { reason: 'Invalid password' }
        );
        throw new UnauthorizedError('Invalid email or password');
    }

    // Check if email is verified
    if (!user.email_verified) {
        throw new UnauthorizedError('Please verify your email before logging in');
    }

    // Create session
    const sessionId = await sessionService.createSession(
        user.id,
        deviceName || null,
        getIpAddress(c.req.raw),
        getUserAgent(c.req.raw)
    );

    // Get user with roles and permissions
    const userWithRoles = await userService.getUserWithRoles(user.id);
    if (!userWithRoles) {
        throw new Error('Failed to load user data');
    }

    // Generate tokens
    const accessToken = await authService.generateAccessToken(userWithRoles);
    const refreshToken = await authService.generateRefreshToken(user.id, sessionId);

    // Log successful login
    await auditService.logEvent(
        AuditEventType.LOGIN_SUCCESS,
        user.id,
        null,
        getIpAddress(c.req.raw),
        getUserAgent(c.req.raw),
        { sessionId }
    );

    return c.json({
        accessToken,
        refreshToken,
        user: {
            id: userWithRoles.id,
            email: userWithRoles.email,
            email_verified: userWithRoles.email_verified,
            roles: userWithRoles.roles.map(r => r.name),
            permissions: userWithRoles.permissions.map(p => p.name),
        },
    });
});

// POST /auth/refresh
auth.post('/refresh', async (c) => {
    const { refreshToken } = await validateBody(c.req.raw, refreshTokenSchema);

    const authService = new AuthService(c.env, c.env.DB);
    const userService = new UserService(c.env.DB);
    const auditService = new AuditService(c.env.DB);

    try {
        // Verify and consume refresh token (implements rotation)
        const { userId, sessionId } = await authService.verifyRefreshToken(refreshToken);

        // Get user with roles
        const user = await userService.getUserWithRoles(userId);
        if (!user) {
            throw new UnauthorizedError('User not found');
        }

        // Generate new tokens
        const newAccessToken = await authService.generateAccessToken(user);
        const newRefreshToken = await authService.generateRefreshToken(userId, sessionId);

        // Log token refresh
        await auditService.logEvent(
            AuditEventType.REFRESH_TOKEN,
            userId,
            null,
            getIpAddress(c.req.raw),
            getUserAgent(c.req.raw),
            { sessionId }
        );

        return c.json({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
        });
    } catch (error) {
        // Refresh token verification handles reuse detection and session revocation
        throw error;
    }
});

// POST /auth/logout
auth.post('/logout', authMiddleware, async (c) => {
    const { refreshToken } = await c.req.json();

    if (!refreshToken) {
        throw new UnauthorizedError('Refresh token required');
    }

    const authService = new AuthService(c.env, c.env.DB);
    const auditService = new AuditService(c.env.DB);
    const auth = c.get('authContext');

    const tokenHash = hashToken(refreshToken);

    // Find the session for this token
    const result = await c.env.DB
        .prepare(
            `SELECT session_id FROM refresh_tokens WHERE token_hash = ?`
        )
        .bind(tokenHash)
        .first<{ session_id: string }>();

    if (result) {
        await authService.revokeSession(result.session_id);

        // Log logout
        await auditService.logEvent(
            AuditEventType.LOGOUT,
            auth.user.id,
            null,
            getIpAddress(c.req.raw),
            getUserAgent(c.req.raw),
            { sessionId: result.session_id }
        );
    }

    return c.json({ message: 'Logged out successfully' });
});

// POST /auth/forgot-password
auth.post('/forgot-password', forgotPasswordRateLimit, async (c) => {
    const { email } = await validateBody(c.req.raw, forgotPasswordSchema);

    const userService = new UserService(c.env.DB);
    const authService = new AuthService(c.env, c.env.DB);
    const auditService = new AuditService(c.env.DB);

    const user = await userService.getUserByEmail(email);

    // Always return success to avoid email enumeration
    if (!user) {
        return c.json({
            message: 'If an account with that email exists, a password reset link has been sent.'
        });
    }

    // Generate reset token
    const resetToken = await authService.generatePasswordResetToken(user.id);

    // Send reset email (dev mode)
    const emailTemplate = generatePasswordResetEmail(
        email,
        resetToken,
        c.env.FRONTEND_URL
    );
    const emailResult = sendEmailDev(emailTemplate);

    // Log password reset request
    await auditService.logEvent(
        AuditEventType.PASSWORD_RESET_REQUESTED,
        user.id,
        null,
        getIpAddress(c.req.raw),
        getUserAgent(c.req.raw)
    );

    return c.json({
        message: 'If an account with that email exists, a password reset link has been sent.',
        // In dev mode, return the reset link
        ...(emailResult.link ? { resetLink: emailResult.link } : {}),
    });
});

// POST /auth/reset-password
auth.post('/reset-password', async (c) => {
    const { token, newPassword } = await validateBody(c.req.raw, resetPasswordSchema);

    const userService = new UserService(c.env.DB);
    const authService = new AuthService(c.env, c.env.DB);
    const auditService = new AuditService(c.env.DB);
    const tokenHash = hashToken(token);

    // Find the reset token
    const result = await c.env.DB
        .prepare(
            `SELECT * FROM password_reset_tokens 
       WHERE token_hash = ? AND used_at IS NULL`
        )
        .bind(tokenHash)
        .first<{ user_id: number; expires_at: string }>();

    if (!result) {
        throw new UnauthorizedError('Invalid or already used reset token');
    }

    // Check if expired
    if (new Date(result.expires_at) < new Date()) {
        throw new UnauthorizedError('Reset token has expired');
    }

    // Hash new password and update
    const newPasswordHash = await authService.hashPassword(newPassword);
    await userService.updatePassword(result.user_id, newPasswordHash);

    // Mark token as used
    await c.env.DB
        .prepare('UPDATE password_reset_tokens SET used_at = datetime(\'now\') WHERE token_hash = ?')
        .bind(tokenHash)
        .run();

    // Revoke all sessions (force re-login with new password)
    await authService.revokeAllSessions(result.user_id);

    // Log password reset completion
    await auditService.logEvent(
        AuditEventType.PASSWORD_RESET_COMPLETED,
        result.user_id,
        null,
        getIpAddress(c.req.raw),
        getUserAgent(c.req.raw)
    );

    return c.json({ message: 'Password reset successfully. Please log in with your new password.' });
});

// POST /auth/change-password (requires authentication)
auth.post('/change-password', authMiddleware, async (c) => {
    const { currentPassword, newPassword } = await validateBody(c.req.raw, changePasswordSchema);

    const userService = new UserService(c.env.DB);
    const authService = new AuthService(c.env, c.env.DB);
    const auditService = new AuditService(c.env.DB);
    const auth = c.get('authContext');

    const user = await userService.getUserById(auth.user.id);
    if (!user) {
        throw new NotFoundError('User not found');
    }

    // Verify current password
    const isValidPassword = await authService.verifyPassword(currentPassword, user.password_hash);
    if (!isValidPassword) {
        throw new UnauthorizedError('Current password is incorrect');
    }

    // Hash and update new password
    const newPasswordHash = await authService.hashPassword(newPassword);
    await userService.updatePassword(user.id, newPasswordHash);

    // Log password change
    await auditService.logEvent(
        AuditEventType.PASSWORD_CHANGED,
        user.id,
        null,
        getIpAddress(c.req.raw),
        getUserAgent(c.req.raw)
    );

    return c.json({ message: 'Password changed successfully' });
});

export default auth;

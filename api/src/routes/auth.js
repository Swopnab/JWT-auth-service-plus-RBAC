// Authentication routes (Vanilla JavaScript - Core functionality only)

import { Hono } from 'hono';
import { AuthService } from '../services/auth.service.js';
import { UserService } from '../services/user.service.js';
import { EmailService } from '../services/email.service.js';
import { getIpAddress, getUserAgent, generateSessionId, isStrongPassword, hashToken } from '../utils/crypto.js';
import { loginRateLimit, registerRateLimit, forgotPasswordRateLimit } from '../middleware/rateLimit.js';
import { authMiddleware, getAuthContext } from '../middleware/auth.js';
import { UnauthorizedError, NotFoundError, ConflictError, ValidationError } from '../utils/errors.js';
import { formatDateForDB } from '../config.js';

const auth = new Hono();

// POST /auth/register
auth.post('/register', registerRateLimit, async (c) => {
    const body = await c.req.json();
    const { email, password } = body;

    // Basic validation
    if (!email || !password) {
        throw new ValidationError('Email and password are required');
    }

    // Password strength check
    const { valid, errors } = isStrongPassword(password);
    if (!valid) {
        throw new ValidationError('Password is too weak', { password: errors });
    }

    const userService = new UserService(c.env.DB);
    const authService = new AuthService(c.env, c.env.DB);
    const emailService = new EmailService(c.env);

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

    // Send verification email
    await emailService.sendVerificationEmail(email, verificationToken);

    return c.json({
        message: 'Registration successful. Please check your email to verify your account.',
        user: {
            id: user.id,
            email: user.email,
            email_verified: false,
        },
    }, 201);
});

// POST /auth/login
auth.post('/login', loginRateLimit, async (c) => {
    const body = await c.req.json();
    const { email, password, deviceName } = body;

    if (!email || !password) {
        throw new ValidationError('Email and password are required');
    }

    const userService = new UserService(c.env.DB);
    const authService = new AuthService(c.env, c.env.DB);

    // Get user
    const user = await userService.getUserByEmail(email);
    if (!user) {
        throw new UnauthorizedError('Invalid credentials');
    }

    // Verify password
    const isValid = await authService.verifyPassword(password, user.password_hash);
    if (!isValid) {
        throw new UnauthorizedError('Invalid credentials');
    }

    // Create session
    const sessionId = generateSessionId();
    const ipAddress = getIpAddress(c.req.raw);
    const userAgent = getUserAgent(c.req.raw);

    await c.env.DB
        .prepare(
            'INSERT INTO sessions (id, user_id, device_name, ip_address, user_agent, last_activity) VALUES (?, ?, ?, ?, ?, datetime(\'now\'))'
        )
        .bind(sessionId, user.id, deviceName || null, ipAddress, userAgent)
        .run();

    // Generate tokens
    const userWithRoles = await userService.getUserWithRoles(user.id);
    const accessToken = await authService.generateAccessToken(userWithRoles);
    const refreshToken = await authService.generateRefreshToken(user.id, sessionId);

    return c.json({
        accessToken,
        refreshToken,
        user: {
            id: userWithRoles.id,
            email: userWithRoles.email,
            email_verified: userWithRoles.email_verified === 1,
            roles: userWithRoles.roles,
            permissions: userWithRoles.permissions,
        },
    });
});

// POST /auth/refresh
auth.post('/refresh', async (c) => {
    const body = await c.req.json();
    const { refreshToken } = body;

    if (!refreshToken) {
        throw new ValidationError('Refresh token is required');
    }

    const authService = new AuthService(c.env, c.env.DB);
    const userService = new UserService(c.env.DB);

    // Verify refresh token
    const { userId, sessionId } = await authService.verifyRefreshToken(refreshToken);

    // Get user with roles
    const user = await userService.getUserWithRoles(userId);
    if (!user) {
        throw new UnauthorizedError('User not found');
    }

    // Generate new tokens
    const newAccessToken = await authService.generateAccessToken(user);
    const newRefreshToken = await authService.generateRefreshToken(userId, sessionId);

    return c.json({
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
    });
});

// POST /auth/logout  
auth.post('/logout', authMiddleware, async (c) => {
    const { user } = getAuthContext(c);
    const body = await c.req.json();
    const { refreshToken } = body;

    if (refreshToken) {
        const tokenHash = hashToken(refreshToken);

        // Revoke the refresh token
        await c.env.DB
            .prepare('UPDATE refresh_tokens SET revoked_at = datetime(\'now\') WHERE token_hash = ?')
            .bind(tokenHash)
            .run();
    }

    return c.json({ message: 'Logged out successfully' });
});

// POST /auth/forgot-password
auth.post('/forgot-password', forgotPasswordRateLimit, async (c) => {
    const body = await c.req.json();
    const { email } = body;

    if (!email) {
        throw new ValidationError('Email is required');
    }

    const userService = new UserService(c.env.DB);
    const authService = new AuthService(c.env, c.env.DB);
    const emailService = new EmailService(c.env);

    const user = await userService.getUserByEmail(email);

    // Always return success to prevent email enumeration
    if (!user) {
        return c.json({ message: 'If the email exists, a reset link will be sent.' });
    }

    // Generate reset token
    const resetToken = await authService.generatePasswordResetToken(user.id);

    // Send reset email
    await emailService.sendPasswordResetEmail(email, resetToken);

    return c.json({ message: 'If the email exists, a reset link will be sent.' });
});

// POST /auth/reset-password
auth.post('/reset-password', async (c) => {
    const body = await c.req.json();
    const { token, newPassword } = body;

    if (!token || !newPassword) {
        throw new ValidationError('Token and new password are required');
    }

    // Password strength check
    const { valid, errors } = isStrongPassword(newPassword);
    if (!valid) {
        throw new ValidationError('Password is too weak', { password: errors });
    }

    const tokenHash = hashToken(token);

    // Find and validate reset token
    const resetRecord = await c.env.DB
        .prepare('SELECT * FROM password_reset_tokens WHERE token_hash = ? AND used_at IS NULL')
        .bind(tokenHash)
        .first();

    if (!resetRecord) {
        throw new UnauthorizedError('Invalid or expired reset token');
    }

    if (new Date(resetRecord.expires_at) < new Date()) {
        throw new UnauthorizedError('Reset token has expired');
    }

    // Update password
    const authService = new AuthService(c.env, c.env.DB);
    const userService = new UserService(c.env.DB);

    const newPasswordHash = await authService.hashPassword(newPassword);
    await userService.updatePassword(resetRecord.user_id, newPasswordHash);

    // Mark token as used
    await c.env.DB
        .prepare('UPDATE password_reset_tokens SET used_at = datetime(\'now\') WHERE token_hash = ?')
        .bind(tokenHash)
        .run();

    // Revoke all sessions for security
    await authService.revokeAllSessions(resetRecord.user_id);

    return c.json({ message: 'Password reset successful. Please log in with your new password.' });
});

export default auth;

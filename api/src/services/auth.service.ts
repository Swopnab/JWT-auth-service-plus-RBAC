// Authentication service - handles password hashing, JWT generation, token management

import bcrypt from 'bcryptjs';
import { SignJWT, jwtVerify } from 'jose';
import type { Env, AccessTokenPayload, RefreshTokenPayload, UserWithRoles } from '../types';
import { config, parseDuration, addSeconds, formatDateForDB } from '../config';
import { generateSecureToken, hashToken } from '../utils/crypto';
import { UnauthorizedError } from '../utils/errors';

export class AuthService {
    constructor(private env: Env, private db: D1Database) { }

    // Hash password using bcrypt
    async hashPassword(password: string): Promise<string> {
        return bcrypt.hash(password, config.BCRYPT_ROUNDS);
    }

    // Verify password against hash
    async verifyPassword(password: string, hash: string): Promise<boolean> {
        return bcrypt.compare(password, hash);
    }

    // Generate access token (short-lived)
    async generateAccessToken(user: UserWithRoles): Promise<string> {
        const payload: AccessTokenPayload = {
            sub: user.id,
            email: user.email,
            roles: user.roles.map(r => r.name),
            permissions: user.permissions.map(p => p.name),
            type: 'access',
        };

        const secret = new TextEncoder().encode(this.env.JWT_ACCESS_SECRET);
        const expiry = parseDuration(this.env.ACCESS_TOKEN_EXPIRY || '15m');

        return new SignJWT(payload as any)
            .setProtectedHeader({ alg: 'HS256' })
            .setIssuedAt()
            .setExpirationTime(Math.floor(Date.now() / 1000) + expiry)
            .sign(secret);
    }

    // Generate refresh token (long-lived)
    async generateRefreshToken(userId: number, sessionId: string): Promise<string> {
        const token = generateSecureToken(32);
        const tokenHash = hashToken(token);

        const expiry = parseDuration(this.env.REFRESH_TOKEN_EXPIRY || '7d');
        const expiresAt = addSeconds(expiry);

        // Store hashed token in database
        await this.db
            .prepare(
                'INSERT INTO refresh_tokens (session_id, token_hash, expires_at) VALUES (?, ?, ?)'
            )
            .bind(sessionId, tokenHash, formatDateForDB(expiresAt))
            .run();

        // Return the raw token to the client
        return token;
    }

    // Verify access token
    async verifyAccessToken(token: string): Promise<AccessTokenPayload> {
        try {
            const secret = new TextEncoder().encode(this.env.JWT_ACCESS_SECRET);
            const { payload } = await jwtVerify(token, secret);

            if (payload.type !== 'access') {
                throw new UnauthorizedError('Invalid token type');
            }

            return payload as unknown as AccessTokenPayload;
        } catch (error) {
            throw new UnauthorizedError('Invalid or expired access token');
        }
    }

    // Verify and consume refresh token (implements rotation)
    async verifyRefreshToken(token: string): Promise<{ userId: number; sessionId: string }> {
        const tokenHash = hashToken(token);

        // Find the token in database
        const result = await this.db
            .prepare(
                `SELECT rt.*, s.user_id 
         FROM refresh_tokens rt 
         JOIN sessions s ON rt.session_id = s.id 
         WHERE rt.token_hash = ?`
            )
            .bind(tokenHash)
            .first<{ user_id: number; session_id: string; expires_at: string; revoked_at: string | null }>();

        if (!result) {
            // Token reuse detected! Revoke entire session
            throw new UnauthorizedError('Invalid refresh token - possible reuse detected');
        }

        // Check if token is revoked
        if (result.revoked_at) {
            // Token was already used - this is reuse! Revoke the session
            await this.revokeSession(result.session_id);
            throw new UnauthorizedError('Refresh token reused - session revoked for security');
        }

        // Check if token is expired
        if (new Date(result.expires_at) < new Date()) {
            throw new UnauthorizedError('Refresh token expired');
        }

        // Mark this token as revoked (consumed)
        await this.db
            .prepare('UPDATE refresh_tokens SET revoked_at = datetime(\'now\') WHERE token_hash = ?')
            .bind(tokenHash)
            .run();

        return {
            userId: result.user_id,
            sessionId: result.session_id,
        };
    }

    // Revoke a specific session (and all its refresh tokens)
    async revokeSession(sessionId: string): Promise<void> {
        await this.db
            .prepare('UPDATE refresh_tokens SET revoked_at = datetime(\'now\') WHERE session_id = ?')
            .bind(sessionId)
            .run();

        await this.db
            .prepare('DELETE FROM sessions WHERE id = ?')
            .bind(sessionId)
            .run();
    }

    // Revoke all sessions for a user
    async revokeAllSessions(userId: number, exceptSessionId?: string): Promise<void> {
        if (exceptSessionId) {
            // Revoke all except current session
            await this.db
                .prepare(
                    `UPDATE refresh_tokens 
           SET revoked_at = datetime('now') 
           WHERE session_id IN (
             SELECT id FROM sessions WHERE user_id = ? AND id != ?
           )`
                )
                .bind(userId, exceptSessionId)
                .run();

            await this.db
                .prepare('DELETE FROM sessions WHERE user_id = ? AND id != ?')
                .bind(userId, exceptSessionId)
                .run();
        } else {
            // Revoke all sessions
            await this.db
                .prepare(
                    `UPDATE refresh_tokens 
           SET revoked_at = datetime('now') 
           WHERE session_id IN (
             SELECT id FROM sessions WHERE user_id = ?
           )`
                )
                .bind(userId)
                .run();

            await this.db
                .prepare('DELETE FROM sessions WHERE user_id = ?')
                .bind(userId)
                .run();
        }
    }

    // Generate email verification token
    async generateEmailVerificationToken(userId: number): Promise<string> {
        const token = generateSecureToken(32);
        const tokenHash = hashToken(token);
        const expiresAt = addSeconds(config.EMAIL_VERIFICATION_EXPIRY);

        await this.db
            .prepare(
                'INSERT INTO email_verification_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)'
            )
            .bind(userId, tokenHash, formatDateForDB(expiresAt))
            .run();

        return token;
    }

    // Generate password reset token
    async generatePasswordResetToken(userId: number): Promise<string> {
        const token = generateSecureToken(32);
        const tokenHash = hashToken(token);
        const expiresAt = addSeconds(config.PASSWORD_RESET_EXPIRY);

        // Invalidate any existing reset tokens for this user
        await this.db
            .prepare('UPDATE password_reset_tokens SET used_at = datetime(\'now\') WHERE user_id = ? AND used_at IS NULL')
            .bind(userId)
            .run();

        await this.db
            .prepare(
                'INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)'
            )
            .bind(userId, tokenHash, formatDateForDB(expiresAt))
            .run();

        return token;
    }
}

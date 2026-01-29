// Authentication service - handles password hashing, JWT generation, token management
// Vanilla JavaScript version

import { SignJWT, jwtVerify } from 'jose';
import { config, parseDuration, addSeconds, formatDateForDB } from '../config.js';
import { generateSecureToken, hashToken } from '../utils/crypto.js';
import { UnauthorizedError } from '../utils/errors.js';

export class AuthService {
    /**
     * @param {Object} env - Cloudflare environment bindings
     * @param {D1Database} db - D1 database instance
     */
    constructor(env, db) {
        this.env = env;
        this.db = db;
    }

    /**
     * Hash password using Web Crypto API (PBKDF2)
     * @param {string} password - Plain text password
     * @returns {Promise<string>} Hashed password
     */
    async hashPassword(password) {
        const encoder = new TextEncoder();
        const passwordBytes = encoder.encode(password);

        // Generate random salt
        const salt = crypto.getRandomValues(new Uint8Array(16));

        // Derive key using PBKDF2 (Workers-friendly)
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            passwordBytes,
            'PBKDF2',
            false,
            ['deriveBits']
        );

        const derivedBits = await crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            256
        );

        // Combine salt + hash
        const hashArray = new Uint8Array(derivedBits);
        const combined = new Uint8Array(salt.length + hashArray.length);
        combined.set(salt);
        combined.set(hashArray, salt.length);

        // Return as base64
        return btoa(String.fromCharCode(...combined));
    }

    /**
     * Verify password against hash
     * @param {string} password - Plain text password
     * @param {string} hash - Hashed password
     * @returns {Promise<boolean>} True if password matches
     */
    async verifyPassword(password, hash) {
        try {
            const encoder = new TextEncoder();
            const passwordBytes = encoder.encode(password);

            // Decode the hash
            const combined = Uint8Array.from(atob(hash), c => c.charCodeAt(0));
            const salt = combined.slice(0, 16);
            const originalHash = combined.slice(16);

            // Derive key with same parameters
            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                passwordBytes,
                'PBKDF2',
                false,
                ['deriveBits']
            );

            const derivedBits = await crypto.subtle.deriveBits(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: 100000,
                    hash: 'SHA-256'
                },
                keyMaterial,
                256
            );

            const newHash = new Uint8Array(derivedBits);

            // Constant-time comparison
            if (newHash.length !== originalHash.length) return false;

            let diff = 0;
            for (let i = 0; i < newHash.length; i++) {
                diff |= newHash[i] ^ originalHash[i];
            }

            return diff === 0;
        } catch (error) {
            return false;
        }
    }

    /**
     * Generate access token (short-lived)
     * @param {Object} user - User object with roles and permissions
     * @returns {Promise<string>} JSON Web Token
     */
    async generateAccessToken(user) {
        const payload = {
            sub: user.id,
            email: user.email,
            roles: user.roles.map(r => r.name),
            permissions: user.permissions.map(p => p.name),
            type: 'access',
        };

        const secret = new TextEncoder().encode(this.env.JWT_ACCESS_SECRET);
        const expiry = parseDuration(this.env.ACCESS_TOKEN_EXPIRY || '15m');

        return new SignJWT(payload)
            .setProtectedHeader({ alg: 'HS256' })
            .setIssuedAt()
            .setExpirationTime(Math.floor(Date.now() / 1000) + expiry)
            .sign(secret);
    }

    /**
     * Generate refresh token (long-lived)
     * @param {number} userId - User ID
     * @param {string} sessionId - Session ID
     * @returns {Promise<string>} Refresh token
     */
    async generateRefreshToken(userId, sessionId) {
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

    /**
     * Verify access token
     * @param {string} token - JWT token
     * @returns {Promise<Object>} Access token payload
     */
    async verifyAccessToken(token) {
        try {
            const secret = new TextEncoder().encode(this.env.JWT_ACCESS_SECRET);
            const { payload } = await jwtVerify(token, secret);

            if (payload.type !== 'access') {
                throw new UnauthorizedError('Invalid token type');
            }

            return payload;
        } catch (error) {
            throw new UnauthorizedError('Invalid or expired access token');
        }
    }

    /**
     * Verify and consume refresh token (implements rotation)
     * @param {string} token - Refresh token
     * @returns {Promise<{userId: number, sessionId: string}>} Token data
     */
    async verifyRefreshToken(token) {
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
            .first();

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

    /**
     * Revoke a specific session (and all its refresh tokens)
     * @param {string} sessionId - Session ID
     * @returns {Promise<void>}
     */
    async revokeSession(sessionId) {
        await this.db
            .prepare('UPDATE refresh_tokens SET revoked_at = datetime(\'now\') WHERE session_id = ?')
            .bind(sessionId)
            .run();

        await this.db
            .prepare('DELETE FROM sessions WHERE id = ?')
            .bind(sessionId)
            .run();
    }

    /**
     * Revoke all sessions for a user
     * @param {number} userId - User ID
     * @param {string} [exceptSessionId] - Session ID to keep active
     * @returns {Promise<void>}
     */
    async revokeAllSessions(userId, exceptSessionId) {
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

    /**
     * Generate email verification token
     * @param {number} userId - User ID
     * @returns {Promise<string>} Verification token
     */
    async generateEmailVerificationToken(userId) {
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

    /**
     * Generate password reset token
     * @param {number} userId - User ID
     * @returns {Promise<string>} Reset token
     */
    async generatePasswordResetToken(userId) {
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

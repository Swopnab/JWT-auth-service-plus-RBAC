// Session management service

import type { Session, SessionWithUser } from '../types';
import { generateSessionId } from '../utils/crypto';
import { NotFoundError } from '../utils/errors';

export class SessionService {
    constructor(private db: D1Database) { }

    // Create a new session
    async createSession(
        userId: number,
        deviceName: string | null,
        ipAddress: string | null,
        userAgent: string | null
    ): Promise<string> {
        const sessionId = generateSessionId();

        await this.db
            .prepare(
                `INSERT INTO sessions (id, user_id, device_name, ip_address, user_agent) 
         VALUES (?, ?, ?, ?, ?)`
            )
            .bind(sessionId, userId, deviceName, ipAddress, userAgent)
            .run();

        return sessionId;
    }

    // Get session by ID
    async getSession(sessionId: string): Promise<Session | null> {
        const result = await this.db
            .prepare('SELECT * FROM sessions WHERE id = ?')
            .bind(sessionId)
            .first<Session>();

        return result || null;
    }

    // Get all sessions for a user
    async getUserSessions(userId: number): Promise<Session[]> {
        const result = await this.db
            .prepare(
                `SELECT * FROM sessions 
         WHERE user_id = ? 
         ORDER BY last_activity DESC`
            )
            .bind(userId)
            .all<Session>();

        return result.results || [];
    }

    // Update session last activity
    async updateSessionActivity(sessionId: string): Promise<void> {
        await this.db
            .prepare('UPDATE sessions SET last_activity = datetime(\'now\') WHERE id = ?')
            .bind(sessionId)
            .run();
    }

    // Delete session
    async deleteSession(sessionId: string): Promise<void> {
        await this.db
            .prepare('DELETE FROM sessions WHERE id = ?')
            .bind(sessionId)
            .run();
    }

    // Verify user owns session
    async verifySessionOwnership(sessionId: string, userId: number): Promise<boolean> {
        const session = await this.getSession(sessionId);
        return session !== null && session.user_id === userId;
    }
}

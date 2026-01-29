// Audit logging service

import type { AuditEventType } from '../config';

export class AuditService {
    constructor(private db: D1Database) { }

    // Log an audit event
    async logEvent(
        eventType: AuditEventType,
        actorUserId: number | null,
        targetUserId: number | null,
        ipAddress: string | null,
        userAgent: string | null,
        metadata?: Record<string, any>
    ): Promise<void> {
        const metadataJson = metadata ? JSON.stringify(metadata) : null;

        await this.db
            .prepare(
                `INSERT INTO audit_logs (event_type, actor_user_id, target_user_id, ip_address, user_agent, metadata)
         VALUES (?, ?, ?, ?, ?, ?)`
            )
            .bind(
                eventType,
                actorUserId,
                targetUserId,
                ipAddress,
                userAgent,
                metadataJson
            )
            .run();
    }

    // Get audit logs with filters
    async getLogs(options: {
        eventType?: string;
        userId?: number;
        startDate?: string;
        endDate?: string;
        page?: number;
        limit?: number;
    }): Promise<any[]> {
        const { eventType, userId, startDate, endDate, page = 1, limit = 20 } = options;
        const offset = (page - 1) * limit;

        let query = 'SELECT * FROM audit_logs WHERE 1=1';
        const bindings: any[] = [];

        if (eventType) {
            query += ' AND event_type = ?';
            bindings.push(eventType);
        }

        if (userId) {
            query += ' AND (actor_user_id = ? OR target_user_id = ?)';
            bindings.push(userId, userId);
        }

        if (startDate) {
            query += ' AND created_at >= ?';
            bindings.push(startDate);
        }

        if (endDate) {
            query += ' AND created_at <= ?';
            bindings.push(endDate);
        }

        query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
        bindings.push(limit, offset);

        const result = await this.db
            .prepare(query)
            .bind(...bindings)
            .all();

        return result.results || [];
    }

    // Get audit log count
    async getLogCount(options: {
        eventType?: string;
        userId?: number;
        startDate?: string;
        endDate?: string;
    }): Promise<number> {
        const { eventType, userId, startDate, endDate } = options;

        let query = 'SELECT COUNT(*) as count FROM audit_logs WHERE 1=1';
        const bindings: any[] = [];

        if (eventType) {
            query += ' AND event_type = ?';
            bindings.push(eventType);
        }

        if (userId) {
            query += ' AND (actor_user_id = ? OR target_user_id = ?)';
            bindings.push(userId, userId);
        }

        if (startDate) {
            query += ' AND created_at >= ?';
            bindings.push(startDate);
        }

        if (endDate) {
            query += ' AND created_at <= ?';
            bindings.push(endDate);
        }

        const result = await this.db
            .prepare(query)
            .bind(...bindings)
            .first<{ count: number }>();

        return result?.count || 0;
    }
}

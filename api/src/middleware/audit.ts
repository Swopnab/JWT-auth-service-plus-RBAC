// Audit logging middleware for sensitive operations

import type { Context, Next } from 'hono';
import type { Env, AuditEventType } from '../types';
import { AuditService } from '../services/audit.service';
import { getAuthContext } from './auth';
import { getIpAddress, getUserAgent } from '../utils/crypto';

export function auditLog(eventType: AuditEventType, getTargetUserId?: (c: Context) => number | null) {
    return async (c: Context<{ Bindings: Env }>, next: Next) => {
        const auditService = new AuditService(c.env.DB);

        // Get request info
        const ipAddress = getIpAddress(c.req.raw);
        const userAgent = getUserAgent(c.req.raw);

        // Try to get authenticated user (may not exist for some events like login)
        let actorUserId: number | null = null;
        try {
            const auth = getAuthContext(c);
            actorUserId = auth.user.id;
        } catch {
            // Not authenticated - this is fine for events like register, login
        }

        // Get target user ID if applicable
        const targetUserId = getTargetUserId ? getTargetUserId(c) : null;

        // Continue with request
        await next();

        // Log the event after successful request
        await auditService.logEvent(
            eventType,
            actorUserId,
            targetUserId,
            ipAddress,
            userAgent
        );
    };
}

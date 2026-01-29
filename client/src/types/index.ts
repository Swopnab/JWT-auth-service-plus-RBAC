// TypeScript types for frontend

export interface User {
    id: number;
    email: string;
    email_verified: boolean;
    roles: string[];
    permissions: string[];
    created_at?: string;
}

export interface Session {
    id: string;
    device_name: string | null;
    ip_address: string | null;
    user_agent: string | null;
    last_activity: string;
    created_at: string;
}

export interface LoginRequest {
    email: string;
    password: string;
    deviceName?: string;
}

export interface LoginResponse {
    accessToken: string;
    refreshToken: string;
    user: User;
}

export interface RegisterRequest {
    email: string;
    password: string;
}

export interface AuditLog {
    id: number;
    event_type: string;
    actor_user_id: number | null;
    target_user_id: number | null;
    ip_address: string | null;
    user_agent: string | null;
    metadata: string | null;
    created_at: string;
}

export interface AnalyticsData {
    users: {
        total: number;
        verified: number;
        verificationRate: string;
    };
    logins: {
        total: number;
        successful: number;
        failed: number;
        successRate: string;
    };
    sessions: {
        active: number;
    };
}

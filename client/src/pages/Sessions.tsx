import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import * as authApi from '../services/auth.api';
import { Monitor, Smartphone, Trash2, AlertTriangle } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import type { Session } from '../types';

export default function Sessions() {
    const queryClient = useQueryClient();

    const { data, isLoading } = useQuery({
        queryKey: ['sessions'],
        queryFn: authApi.getSessions,
    });

    const revokeSession = useMutation({
        mutationFn: authApi.revokeSession,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['sessions'] });
            toast.success('Session revoked');
        },
        onError: () => {
            toast.error('Failed to revoke session');
        },
    });

    const revokeAllSessions = useMutation({
        mutationFn: authApi.revokeAllSessions,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['sessions'] });
            toast.success('All sessions revoked');
        },
        onError: () => {
            toast.error('Failed to revoke sessions');
        },
    });

    const sessions: Session[] = data?.sessions || [];

    return (
        <div>
            <div className="flex justify-between items-center mb-xl">
                <div>
                    <h1>Active Sessions</h1>
                    <p className="text-secondary">Manage your logged-in devices</p>
                </div>
                {sessions.length > 1 && (
                    <button
                        onClick={() => revokeAllSessions.mutate()}
                        className="btn btn-danger"
                        disabled={revokeAllSessions.isPending}
                    >
                        <AlertTriangle size={16} />
                        Revoke All Sessions
                    </button>
                )}
            </div>

            {isLoading ? (
                <div className="flex justify-center items-center" style={{ padding: '3rem' }}>
                    <div className="spinner" />
                </div>
            ) : sessions.length === 0 ? (
                <div className="card text-center" style={{ padding: '3rem' }}>
                    <Monitor size={48} style={{ color: 'var(--color-text-tertiary)', margin: '0 auto var(--spacing-md)' }} />
                    <p className="text-secondary">No active sessions</p>
                </div>
            ) : (
                <div style={{ display: 'grid', gap: 'var(--spacing-lg)' }}>
                    {sessions.map((session) => (
                        <div key={session.id} className="card">
                            <div className="flex justify-between items-start">
                                <div className="flex gap-md">
                                    {session.device_name?.toLowerCase().includes('mobile') ||
                                        session.user_agent?.toLowerCase().includes('mobile') ? (
                                        <Smartphone size={24} style={{ color: 'var(--color-primary)' }} />
                                    ) : (
                                        <Monitor size={24} style={{ color: 'var(--color-primary)' }} />
                                    )}
                                    <div>
                                        <h4 style={{ marginBottom: 'var(--spacing-xs)' }}>
                                            {session.device_name || 'Unknown Device'}
                                        </h4>
                                        <p className="text-secondary" style={{ fontSize: 'var(--font-size-sm)', margin: 0 }}>
                                            {session.ip_address || 'Unknown IP'}
                                        </p>
                                        <p className="text-tertiary" style={{ fontSize: 'var(--font-size-xs)', margin: 0 }}>
                                            Last active: {formatDistanceToNow(new Date(session.last_activity))} ago
                                        </p>
                                    </div>
                                </div>

                                <button
                                    onClick={() => revokeSession.mutate(session.id)}
                                    className="btn btn-sm btn-danger"
                                    disabled={revokeSession.isPending}
                                >
                                    <Trash2 size={14} />
                                    Revoke
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

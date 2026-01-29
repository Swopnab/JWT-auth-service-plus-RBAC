import { useAuthStore } from '../store/auth.store';
import { Shield, Mail, Calendar, Award } from 'lucide-react';

export default function Dashboard() {
    const user = useAuthStore((state) => state.user);

    if (!user) return null;

    return (
        <div>
            <div className="mb-xl">
                <h1>Dashboard</h1>
                <p className="text-secondary">Welcome back, {user.email}!</p>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 'var(--spacing-lg)' }}>
                <div className="card">
                    <div className="flex items-center gap-md mb-md">
                        <Mail size={24} style={{ color: 'var(--color-primary)' }} />
                        <h3>Email Status</h3>
                    </div>
                    <p style={{ fontSize: 'var(--font-size-2xl)', fontWeight: 600, margin: 0 }}>
                        {user.email_verified ? (
                            <span className="badge badge-success">Verified ✓</span>
                        ) : (
                            <span className="badge badge-warning">Unverified</span>
                        )}
                    </p>
                </div>

                <div className="card">
                    <div className="flex items-center gap-md mb-md">
                        <Shield size={24} style={{ color: 'var(--color-success)' }} />
                        <h3>Roles</h3>
                    </div>
                    <div className="flex gap-sm" style={{ flexWrap: 'wrap' }}>
                        {user.roles.map((role) => (
                            <span key={role} className="badge badge-info">
                                {role}
                            </span>
                        ))}
                    </div>
                </div>

                <div className="card">
                    <div className="flex items-center gap-md mb-md">
                        <Award size={24} style={{ color: 'var(--color-warning)' }} />
                        <h3>Permissions</h3>
                    </div>
                    <p style={{ fontSize: 'var(--font-size-lg)', fontWeight: 600, margin: 0 }}>
                        {user.permissions.length} permissions
                    </p>
                </div>

                <div className="card">
                    <div className="flex items-center gap-md mb-md">
                        <Calendar size={24} style={{ color: 'var(--color-info)' }} />
                        <h3>Member Since</h3>
                    </div>
                    <p style={{ fontSize: 'var(--font-size-sm)', margin: 0 }}>
                        {user.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'}
                    </p>
                </div>
            </div>

            <div className="card mt-xl">
                <h3 className="mb-md">Your Permissions</h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 'var(--spacing-sm)' }}>
                    {user.permissions.map((permission) => (
                        <div key={permission} className="badge badge-info">
                            {permission}
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}

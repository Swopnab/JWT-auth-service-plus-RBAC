import { useAuthStore } from '../store/auth.store';
import { User, Mail, Shield, Key } from 'lucide-react';

export default function Profile() {
    const user = useAuthStore((state) => state.user);

    if (!user) return null;

    return (
        <div>
            <div className="mb-xl">
                <h1>Profile</h1>
                <p className="text-secondary">Your account information</p>
            </div>

            <div className="card" style={{ maxWidth: '700px' }}>
                <div className="card-header">
                    <h3 className="card-title">
                        <User size={20} />
                        Personal Information
                    </h3>
                </div>

                <div style={{ display: 'grid', gap: 'var(--spacing-lg)' }}>
                    <div>
                        <label className="form-label">
                            <Mail size={16} />
                            Email Address
                        </label>
                        <p style={{ margin: 0, fontSize: 'var(--font-size-lg)' }}>{user.email}</p>
                    </div>

                    <div>
                        <label className="form-label">
                            <Shield size={16} />
                            Roles
                        </label>
                        <div className="flex gap-sm" style={{ flexWrap: 'wrap' }}>
                            {user.roles.map((role) => (
                                <span key={role} className="badge badge-info">
                                    {role}
                                </span>
                            ))}
                        </div>
                    </div>

                    <div>
                        <label className="form-label">
                            <Key size={16} />
                            Permissions
                        </label>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 'var(--spacing-sm)' }}>
                            {user.permissions.map((permission) => (
                                <span key={permission} className="badge badge-success" style={{ fontSize: 'var(--font-size-xs)' }}>
                                    {permission}
                                </span>
                            ))}
                        </div>
                    </div>

                    <div>
                        <label className="form-label">Email Verification Status</label>
                        {user.email_verified ? (
                            <span className="badge badge-success">Verified ✓</span>
                        ) : (
                            <span className="badge badge-warning">Unverified</span>
                        )}
                    </div>

                    {user.created_at && (
                        <div>
                            <label className="form-label">Member Since</label>
                            <p style={{ margin: 0 }}>{new Date(user.created_at).toLocaleDateString('en-US', {
                                year: 'numeric',
                                month: 'long',
                                day: 'numeric'
                            })}</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

import { useAuthStore } from '../store/auth.store';

interface PermissionGuardProps {
    permission?: string;
    role?: string;
    children: React.ReactNode;
    fallback?: React.ReactNode;
}

export default function PermissionGuard({
    permission,
    role,
    children,
    fallback
}: PermissionGuardProps) {
    const user = useAuthStore((state) => state.user);

    if (!user) {
        return fallback || <div className="alert alert-error">Unauthorized</div>;
    }

    // Check permission
    if (permission && !user.permissions.includes(permission)) {
        return fallback || (
            <div className="container" style={{ padding: '2rem' }}>
                <div className="alert alert-error">
                    <strong>Access Denied</strong>
                    <p>You don't have permission to view this page. Required permission: {permission}</p>
                </div>
            </div>
        );
    }

    // Check role
    if (role && !user.roles.includes(role)) {
        return fallback || (
            <div className="container" style={{ padding: '2rem' }}>
                <div className="alert alert-error">
                    <strong>Access Denied</strong>
                    <p>You don't have the required role to view this page. Required role: {role}</p>
                </div>
            </div>
        );
    }

    return <>{children}</>;
}

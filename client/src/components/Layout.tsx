import { Outlet, Link, useNavigate } from 'react-router-dom';
import { useAuthStore } from '../store/auth.store';
import { LogOut, User, Settings, Shield, BarChart3, Users, FileText } from 'lucide-react';
import './Layout.css';

export default function Layout() {
    const { user, logout } = useAuthStore();
    const navigate = useNavigate();

    const handleLogout = async () => {
        await logout();
        navigate('/login');
    };

    const hasPermission = (permission: string) => {
        return user?.permissions.includes(permission);
    };

    const hasRole = (role: string) => {
        return user?.roles.includes(role);
    };

    return (
        <div className="layout">
            <header className="header">
                <div className="header-content">
                    <Link to="/dashboard" className="logo">
                        <Shield size={24} />
                        <span>Auth Service</span>
                    </Link>

                    <nav className="nav">
                        <Link to="/dashboard" className="nav-link">Dashboard</Link>
                        <Link to="/sessions" className="nav-link">Sessions</Link>
                        <Link to="/profile" className="nav-link">Profile</Link>

                        {(hasPermission('users.read') || hasPermission('roles.manage') || hasPermission('audit.read') || hasRole('Admin')) && (
                            <div className="nav-dropdown">
                                <button className="nav-link">Admin ▾</button>
                                <div className="dropdown-content">
                                    {hasPermission('users.read') && (
                                        <Link to="/admin/users" className="dropdown-link">
                                            <Users size={16} />
                                            Users
                                        </Link>
                                    )}
                                    {hasPermission('roles.manage') && (
                                        <Link to="/admin/roles" className="dropdown-link">
                                            <Shield size={16} />
                                            Roles
                                        </Link>
                                    )}
                                    {hasPermission('audit.read') && (
                                        <Link to="/admin/audit-logs" className="dropdown-link">
                                            <FileText size={16} />
                                            Audit Logs
                                        </Link>
                                    )}
                                    {hasRole('Admin') && (
                                        <Link to="/admin/analytics" className="dropdown-link">
                                            <BarChart3 size={16} />
                                            Analytics
                                        </Link>
                                    )}
                                </div>
                            </div>
                        )}
                    </nav>

                    <div className="header-actions">
                        <div className="user-menu">
                            <button className="user-button">
                                <User size={20} />
                                <span>{user?.email}</span>
                            </button>
                            <div className="dropdown-content">
                                <Link to="/change-password" className="dropdown-link">
                                    <Settings size={16} />
                                    Change Password
                                </Link>
                                <button onClick={handleLogout} className="dropdown-link">
                                    <LogOut size={16} />
                                    Logout
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </header>

            <main className="main-content">
                <Outlet />
            </main>

            <footer className="footer">
                <div className="footer-content">
                    <p>&copy; 2026 Auth Service. Built with JWT & RBAC.</p>
                    <div className="footer-links">
                        <a href="https://github.com" target="_blank" rel="noopener noreferrer">GitHub</a>
                        <span>•</span>
                        <Link to="/dashboard">Documentation</Link>
                    </div>
                </div>
            </footer>
        </div>
    );
}

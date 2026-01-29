import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useAuthStore } from './store/auth.store';

// Pages
import Login from './pages/Login';
import Register from './pages/Register';
import ForgotPassword from './pages/ForgotPassword';
import ResetPassword from './pages/ResetPassword';
import VerifyEmail from './pages/VerifyEmail';
import Dashboard from './pages/Dashboard';
import Sessions from './pages/Sessions';
import ChangePassword from './pages/ChangePassword';
import Profile from './pages/Profile';
import AdminUsers from './pages/admin/Users';
import AdminUserDetails from './pages/admin/UserDetails';
import AdminRoles from './pages/admin/Roles';
import AdminAuditLogs from './pages/admin/AuditLogs';
import AdminAnalytics from './pages/admin/Analytics';

// Components
import PrivateRoute from './components/PrivateRoute';
import PermissionGuard from './components/PermissionGuard';
import Layout from './components/Layout';

function App() {
    return (
        <BrowserRouter basename="/JWT-auth-service-plus-RBAC">
            <Routes>
                {/* Public Routes */}
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />
                <Route path="/forgot-password" element={<ForgotPassword />} />
                <Route path="/reset-password" element={<ResetPassword />} />
                <Route path="/verify-email" element={<VerifyEmail />} />

                {/* Protected Routes */}
                <Route element={<PrivateRoute><Layout /></PrivateRoute>}>
                    <Route path="/dashboard" element={<Dashboard />} />
                    <Route path="/sessions" element={<Sessions />} />
                    <Route path="/change-password" element={<ChangePassword />} />
                    <Route path="/profile" element={<Profile />} />

                    {/* Admin Routes */}
                    <Route path="/admin/users" element={
                        <PermissionGuard permission="users.read">
                            <AdminUsers />
                        </PermissionGuard>
                    } />
                    <Route path="/admin/users/:id" element={
                        <PermissionGuard permission="users.read">
                            <AdminUserDetails />
                        </PermissionGuard>
                    } />
                    <Route path="/admin/roles" element={
                        <PermissionGuard permission="roles.manage">
                            <AdminRoles />
                        </PermissionGuard>
                    } />
                    <Route path="/admin/audit-logs" element={
                        <PermissionGuard permission="audit.read">
                            <AdminAuditLogs />
                        </PermissionGuard>
                    } />
                    <Route path="/admin/analytics" element={
                        <PermissionGuard role="Admin">
                            <AdminAnalytics />
                        </PermissionGuard>
                    } />
                </Route>

                {/* Default redirect */}
                <Route path="/" element={<Navigate to="/dashboard" replace />} />
                <Route path="*" element={<Navigate to="/dashboard" replace />} />
            </Routes>
        </BrowserRouter>
    );
}

export default App;

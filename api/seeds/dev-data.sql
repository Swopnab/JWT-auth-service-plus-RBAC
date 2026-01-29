-- Development seed data for Auth Service
-- Password for all users: "Password123!"
-- Hash generated with bcrypt (rounds=10): $2a$10$3euPcmQFCiblsZeEu5s7p.e0cGCJj.eVJBvJ5B1PJYZ0y4zt0ORaq

-- Insert default roles
INSERT INTO roles (name, description) VALUES
  ('Admin', 'Full system access with all permissions'),
  ('User', 'Standard user with basic access'),
  ('Moderator', 'Can manage users but not system settings');

-- Insert permissions
INSERT INTO permissions (name, resource, action, description) VALUES
  ('users.read', 'users', 'read', 'View user information'),
  ('users.write', 'users', 'write', 'Create and update users'),
  ('users.delete', 'users', 'delete', 'Delete users'),
  ('roles.manage', 'roles', 'manage', 'Manage roles and permissions'),
  ('audit.read', 'audit', 'read', 'View audit logs'),
  ('analytics.read', 'analytics', 'read', 'View analytics dashboard'),
  ('sessions.manage', 'sessions', 'manage', 'Manage user sessions');

-- Assign permissions to Admin role (all permissions)
INSERT INTO role_permissions (role_id, permission_id)
SELECT 1, id FROM permissions;

-- Assign permissions to User role (basic permissions)
INSERT INTO role_permissions (role_id, permission_id)
SELECT 2, id FROM permissions WHERE name IN ('users.read');

-- Assign permissions to Moderator role
INSERT INTO role_permissions (role_id, permission_id)
SELECT 3, id FROM permissions WHERE name IN ('users.read', 'users.write', 'audit.read');

-- Insert demo users
-- Admin user
INSERT INTO users (email, password_hash, email_verified) VALUES
  ('admin@example.com', '$2a$10$3euPcmQFCiblsZeEu5s7p.e0cGCJj.eVJBvJ5B1PJYZ0y4zt0ORaq', 1);

-- Regular user
INSERT INTO users (email, password_hash, email_verified) VALUES
  ('user@example.com', '$2a$10$3euPcmQFCiblsZeEu5s7p.e0cGCJj.eVJBvJ5B1PJYZ0y4zt0ORaq', 1);

-- Moderator user
INSERT INTO users (email, password_hash, email_verified) VALUES
  ('moderator@example.com', '$2a$10$3euPcmQFCiblsZeEu5s7p.e0cGCJj.eVJBvJ5B1PJYZ0y4zt0ORaq', 1);

-- Assign roles to users
INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES
  (1, 1, NULL),  -- admin@example.com -> Admin role
  (2, 2, 1),     -- user@example.com -> User role (assigned by admin)
  (3, 3, 1);     -- moderator@example.com -> Moderator role (assigned by admin)

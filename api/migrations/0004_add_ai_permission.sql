-- Migration: 0004_add_ai_permission.sql
-- Description: Add use_ai_assistant permission and grant to Admin and User roles

INSERT OR IGNORE INTO permissions (name, resource, action, description)
VALUES ('use_ai_assistant', 'ai', 'use', 'Access and interact with Zabum AI personal assistant');

-- Assign to Admin role
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.name = 'use_ai_assistant'
WHERE r.name = 'Admin';

-- Assign to User role
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.name = 'use_ai_assistant'
WHERE r.name = 'User';

-- Assign to Moderator role
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.name = 'use_ai_assistant'
WHERE r.name = 'Moderator';

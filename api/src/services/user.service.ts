// User service - handles user CRUD and role/permission loading

import type { User, UserWithRoles, Role, Permission } from '../types';
import { NotFoundError, ConflictError } from '../utils/errors';

export class UserService {
    constructor(private db: D1Database) { }

    // Create a new user
    async createUser(email: string, passwordHash: string): Promise<User> {
        try {
            const result = await this.db
                .prepare(
                    'INSERT INTO users (email, password_hash, email_verified) VALUES (?, ?, 0) RETURNING *'
                )
                .bind(email, passwordHash)
                .first<User>();

            if (!result) {
                throw new Error('Failed to create user');
            }

            // Assign default "User" role
            await this.assignRoleByName(result.id, 'User');

            return result;
        } catch (error: any) {
            if (error.message?.includes('UNIQUE constraint failed')) {
                throw new ConflictError('User with this email already exists');
            }
            throw error;
        }
    }

    // Get user by ID
    async getUserById(id: number): Promise<User | null> {
        const result = await this.db
            .prepare('SELECT * FROM users WHERE id = ?')
            .bind(id)
            .first<User>();

        return result || null;
    }

    // Get user by email
    async getUserByEmail(email: string): Promise<User | null> {
        const result = await this.db
            .prepare('SELECT * FROM users WHERE email = ?')
            .bind(email)
            .first<User>();

        return result || null;
    }

    // Get user with roles and permissions
    async getUserWithRoles(id: number): Promise<UserWithRoles | null> {
        const user = await this.getUserById(id);
        if (!user) {
            return null;
        }

        const roles = await this.getUserRoles(id);
        const permissions = await this.getUserPermissions(id);

        return {
            ...user,
            roles,
            permissions,
        };
    }

    // Get all user roles
    async getUserRoles(userId: number): Promise<Role[]> {
        const result = await this.db
            .prepare(
                `SELECT r.* FROM roles r
         JOIN user_roles ur ON r.id = ur.role_id
         WHERE ur.user_id = ?`
            )
            .bind(userId)
            .all<Role>();

        return result.results || [];
    }

    // Get all user permissions (aggregated from roles)
    async getUserPermissions(userId: number): Promise<Permission[]> {
        const result = await this.db
            .prepare(
                `SELECT DISTINCT p.* FROM permissions p
         JOIN role_permissions rp ON p.id = rp.permission_id
         JOIN user_roles ur ON rp.role_id = ur.role_id
         WHERE ur.user_id = ?`
            )
            .bind(userId)
            .all<Permission>();

        return result.results || [];
    }

    // Check if user has permission
    async hasPermission(userId: number, permissionName: string): Promise<boolean> {
        const result = await this.db
            .prepare(
                `SELECT COUNT(*) as count FROM permissions p
         JOIN role_permissions rp ON p.id = rp.permission_id
         JOIN user_roles ur ON rp.role_id = ur.role_id
         WHERE ur.user_id = ? AND p.name = ?`
            )
            .bind(userId, permissionName)
            .first<{ count: number }>();

        return (result?.count || 0) > 0;
    }

    // Update user email verification status
    async markEmailVerified(userId: number): Promise<void> {
        await this.db
            .prepare('UPDATE users SET email_verified = 1, updated_at = datetime(\'now\') WHERE id = ?')
            .bind(userId)
            .run();
    }

    // Update user password
    async updatePassword(userId: number, newPasswordHash: string): Promise<void> {
        await this.db
            .prepare('UPDATE users SET password_hash = ?, updated_at = datetime(\'now\') WHERE id = ?')
            .bind(newPasswordHash, userId)
            .run();
    }

    // Assign role to user (by role ID)
    async assignRole(userId: number, roleId: number, assignedBy?: number): Promise<void> {
        await this.db
            .prepare(
                'INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_by) VALUES (?, ?, ?)'
            )
            .bind(userId, roleId, assignedBy || null)
            .run();
    }

    // Assign role to user (by role name)
    async assignRoleByName(userId: number, roleName: string, assignedBy?: number): Promise<void> {
        const role = await this.db
            .prepare('SELECT id FROM roles WHERE name = ?')
            .bind(roleName)
            .first<{ id: number }>();

        if (!role) {
            throw new NotFoundError(`Role "${roleName}" not found`);
        }

        await this.assignRole(userId, role.id, assignedBy);
    }

    // Remove role from user
    async removeRole(userId: number, roleId: number): Promise<void> {
        await this.db
            .prepare('DELETE FROM user_roles WHERE user_id = ? AND role_id = ?')
            .bind(userId, roleId)
            .run();
    }

    // Get all users (with pagination)
    async getAllUsers(page: number = 1, limit: number = 20): Promise<User[]> {
        const offset = (page - 1) * limit;

        const result = await this.db
            .prepare('SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?')
            .bind(limit, offset)
            .all<User>();

        return result.results || [];
    }

    // Get user count
    async getUserCount(): Promise<number> {
        const result = await this.db
            .prepare('SELECT COUNT(*) as count FROM users')
            .first<{ count: number }>();

        return result?.count || 0;
    }
}

// User service - handles user CRUD and role/permission loading
// Vanilla JavaScript version

import { NotFoundError, ConflictError } from '../utils/errors.js';

export class UserService {
    /**
     * @param {D1Database} db - D1 database instance
     */
    constructor(db) {
        this.db = db;
    }

    /**
     * Create a new user
     * @param {string} email - User email
     * @param {string} passwordHash - Hashed password
     * @returns {Promise<Object>} Created user
     */
    async createUser(email, passwordHash) {
        try {
            const result = await this.db
                .prepare(
                    'INSERT INTO users (email, password_hash, email_verified) VALUES (?, ?, 0) RETURNING *'
                )
                .bind(email, passwordHash)
                .first();

            if (!result) {
                throw new Error('Failed to create user');
            }

            // Assign default "User" role
            await this.assignRoleByName(result.id, 'User');

            return result;
        } catch (error) {
            if (error.message?.includes('UNIQUE constraint failed')) {
                throw new ConflictError('User with this email already exists');
            }
            throw error;
        }
    }

    /**
     * Get user by ID
     * @param {number} id - User ID
     * @returns {Promise<Object|null>} User object or null
     */
    async getUserById(id) {
        const result = await this.db
            .prepare('SELECT * FROM users WHERE id = ?')
            .bind(id)
            .first();

        return result || null;
    }

    /**
     * Get user by email
     * @param {string} email - User email
     * @returns {Promise<Object|null>} User object or null
     */
    async getUserByEmail(email) {
        const result = await this.db
            .prepare('SELECT * FROM users WHERE email = ?')
            .bind(email)
            .first();

        return result || null;
    }

    /**
     * Get user with roles and permissions
     * @param {number} id - User ID
     * @returns {Promise<Object|null>} User with roles and permissions
     */
    async getUserWithRoles(id) {
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

    /**
     * Get all user roles
     * @param {number} userId - User ID
     * @returns {Promise<Array>} Array of roles
     */
    async getUserRoles(userId) {
        const result = await this.db
            .prepare(
                `SELECT r.* FROM roles r
         JOIN user_roles ur ON r.id = ur.role_id
         WHERE ur.user_id = ?`
            )
            .bind(userId)
            .all();

        return result.results || [];
    }

    /**
     * Get all user permissions (aggregated from roles)
     * @param {number} userId - User ID
     * @returns {Promise<Array>} Array of permissions
     */
    async getUserPermissions(userId) {
        const result = await this.db
            .prepare(
                `SELECT DISTINCT p.* FROM permissions p
         JOIN role_permissions rp ON p.id = rp.permission_id
         JOIN user_roles ur ON rp.role_id = ur.role_id
         WHERE ur.user_id = ?`
            )
            .bind(userId)
            .all();

        return result.results || [];
    }

    /**
     * Check if user has permission
     * @param {number} userId - User ID
     * @param {string} permissionName - Permission name
     * @returns {Promise<boolean>} True if user has permission
     */
    async hasPermission(userId, permissionName) {
        const result = await this.db
            .prepare(
                `SELECT COUNT(*) as count FROM permissions p
         JOIN role_permissions rp ON p.id = rp.permission_id
         JOIN user_roles ur ON rp.role_id = ur.role_id
         WHERE ur.user_id = ? AND p.name = ?`
            )
            .bind(userId, permissionName)
            .first();

        return (result?.count || 0) > 0;
    }

    /**
     * Update user email verification status
     * @param {number} userId - User ID
     * @returns {Promise<void>}
     */
    async markEmailVerified(userId) {
        await this.db
            .prepare('UPDATE users SET email_verified = 1, updated_at = datetime(\'now\') WHERE id = ?')
            .bind(userId)
            .run();
    }

    /**
     * Update user password
     * @param {number} userId - User ID
     * @param {string} newPasswordHash - New hashed password
     * @returns {Promise<void>}
     */
    async updatePassword(userId, newPasswordHash) {
        await this.db
            .prepare('UPDATE users SET password_hash = ?, updated_at = datetime(\'now\') WHERE id = ?')
            .bind(newPasswordHash, userId)
            .run();
    }

    /**
     * Assign role to user (by role ID)
     * @param {number} userId - User ID
     * @param {number} roleId - Role ID
     * @param {number} [assignedBy] - ID of user who assigned the role
     * @returns {Promise<void>}
     */
    async assignRole(userId, roleId, assignedBy) {
        await this.db
            .prepare(
                'INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_by) VALUES (?, ?, ?)'
            )
            .bind(userId, roleId, assignedBy || null)
            .run();
    }

    /**
     * Assign role to user (by role name)
     * @param {number} userId - User ID
     * @param {string} roleName - Role name
     * @param {number} [assignedBy] - ID of user who assigned the role
     * @returns {Promise<void>}
     */
    async assignRoleByName(userId, roleName, assignedBy) {
        const role = await this.db
            .prepare('SELECT id FROM roles WHERE name = ?')
            .bind(roleName)
            .first();

        if (!role) {
            throw new NotFoundError(`Role "${roleName}" not found`);
        }

        await this.assignRole(userId, role.id, assignedBy);
    }

    /**
     * Remove role from user
     * @param {number} userId - User ID
     * @param {number} roleId - Role ID
     * @returns {Promise<void>}
     */
    async removeRole(userId, roleId) {
        await this.db
            .prepare('DELETE FROM user_roles WHERE user_id = ? AND role_id = ?')
            .bind(userId, roleId)
            .run();
    }

    /**
     * Get all users (with pagination)
     * @param {number} [page=1] - Page number
     * @param {number} [limit=20] - Items per page
     * @returns {Promise<Array>} Array of users
     */
    async getAllUsers(page = 1, limit = 20) {
        const offset = (page - 1) * limit;

        const result = await this.db
            .prepare('SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?')
            .bind(limit, offset)
            .all();

        return result.results || [];
    }

    /**
     * Get user count
     * @returns {Promise<number>} Total number of users
     */
    async getUserCount() {
        const result = await this.db
            .prepare('SELECT COUNT(*) as count FROM users')
            .first();

        return result?.count || 0;
    }
}

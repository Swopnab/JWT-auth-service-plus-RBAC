// API Configuration - automatically switches between local development and Cloudflare Workers production
const API_BASE_URL = (typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'))
    ? 'http://localhost:8787'
    : 'https://auth-service-api.swopnabbikram.workers.dev';

// JWT Helper Functions
/**
 * Safely parse a JWT payload without external libraries
 * @param {string} token
 * @returns {object|null}
 */
function parseJwt(token) {
    if (!token || typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    try {
        const base64Url = parts[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(
            atob(base64)
                .split('')
                .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
                .join('')
        );
        return JSON.parse(jsonPayload);
    } catch (e) {
        return null;
    }
}

/**
 * Check if a JWT is expired
 * @param {string} token
 * @returns {boolean}
 */
function isTokenExpired(token) {
    const payload = parseJwt(token);
    if (!payload || !payload.exp) return true;
    const currentTime = Math.floor(Date.now() / 1000);
    // Buffer by 5 seconds to prevent edge-case expiration during flight
    return payload.exp <= (currentTime + 5);
}

/**
 * Check if the user is authenticated with a valid or refreshable token in sessionStorage
 * @returns {boolean}
 */
function isLoggedIn() {
    const accessToken = sessionStorage.getItem('accessToken');
    if (!accessToken) return false;
    if (isTokenExpired(accessToken)) {
        return !!sessionStorage.getItem('refreshToken');
    }
    return true;
}

/**
 * Get current user information from token payload / sessionStorage
 * @returns {object|null}
 */
function getCurrentUser() {
    const token = sessionStorage.getItem('accessToken');
    const payload = parseJwt(token);
    const userStr = sessionStorage.getItem('user');

    let storedUser = null;
    if (userStr) {
        try {
            storedUser = JSON.parse(userStr);
        } catch (e) {
            storedUser = null;
        }
    }

    if (payload && payload.sub) {
        return {
            id: payload.sub,
            email: payload.email || storedUser?.email,
            // nickname is never embedded in JWT - always read from storedUser (written by getProfile/updateNickname)
            nickname: storedUser?.nickname ?? null,
            email_verified: storedUser?.email_verified ?? false,
            roles: payload.roles || storedUser?.roles || [],
            permissions: payload.permissions || storedUser?.permissions || []
        };
    }

    return storedUser;
}

/**
 * Get the current raw access token string
 * @returns {string|null}
 */
function getAccessToken() {
    return sessionStorage.getItem('accessToken');
}

/**
 * Check if current user has a specific role (RBAC)
 * @param {string} roleName
 * @returns {boolean}
 */
function hasRole(roleName) {
    const user = getCurrentUser();
    if (!user || !user.roles) return false;
    return user.roles.some(r => (typeof r === 'string' ? r : r.name) === roleName);
}

/**
 * Check if current user has a specific permission (RBAC)
 * @param {string} permissionName
 * @returns {boolean}
 */
function hasPermission(permissionName) {
    const user = getCurrentUser();
    if (!user || !user.permissions) return false;
    return user.permissions.some(p => (typeof p === 'string' ? p : p.name) === permissionName);
}

/**
 * Clear all authentication tokens and session state from storage
 */
function clearAuth() {
    sessionStorage.removeItem('accessToken');
    sessionStorage.removeItem('refreshToken');
    sessionStorage.removeItem('user');
    // Also clean up any legacy localStorage entries to prevent accidental leaks
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('user');
}

/**
 * Redirect user to login page
 */
function redirectToLogin() {
    if (!window.location.pathname.endsWith('index.html') && window.location.pathname !== '/' && !window.location.pathname.endsWith('/')) {
        window.location.href = 'index.html';
    }
}

/**
 * Route Guard: protect pages requiring authentication
 * Verifies JWT validity in sessionStorage, refreshes token if expired, redirects if unauthenticated
 * @param {object} [options]
 * @param {string} [options.requiredRole]
 * @param {string} [options.requiredPermission]
 * @returns {Promise<boolean>}
 */
async function requireAuth(options = {}) {
    const accessToken = sessionStorage.getItem('accessToken');
    const refreshToken = sessionStorage.getItem('refreshToken');

    // 1. If no tokens exist at all in sessionStorage, clear and redirect to login
    if (!accessToken && !refreshToken) {
        clearAuth();
        redirectToLogin();
        return false;
    }

    // 2. If access token is missing or expired, attempt refresh
    let validToken = accessToken;
    if (!validToken || isTokenExpired(validToken)) {
        if (refreshToken) {
            const refreshed = await refreshAccessToken();
            if (!refreshed) {
                clearAuth();
                redirectToLogin();
                return false;
            }
            validToken = sessionStorage.getItem('accessToken');
        } else {
            clearAuth();
            redirectToLogin();
            return false;
        }
    }

    // 3. Validate token format & payload structure
    const payload = parseJwt(validToken);
    if (!payload || !payload.sub || isTokenExpired(validToken)) {
        clearAuth();
        redirectToLogin();
        return false;
    }

    // 4. Verify RBAC requirements if specified
    if (options.requiredRole && !hasRole(options.requiredRole)) {
        alert('Access denied: Insufficient permissions (required role: ' + options.requiredRole + ')');
        window.location.href = 'dashboard.html';
        return false;
    }

    if (options.requiredPermission && !hasPermission(options.requiredPermission)) {
        alert('Access denied: Insufficient permissions (required permission: ' + options.requiredPermission + ')');
        window.location.href = 'dashboard.html';
        return false;
    }

    // 5. Keep user profile in sync in sessionStorage
    if (!sessionStorage.getItem('user')) {
        sessionStorage.setItem('user', JSON.stringify({
            id: payload.sub,
            email: payload.email,
            roles: payload.roles || [],
            permissions: payload.permissions || []
        }));
    }

    return true;
}

/**
 * Redirect already authenticated users away from auth pages (login/register)
 */
async function redirectIfLoggedIn() {
    const accessToken = sessionStorage.getItem('accessToken');
    const refreshToken = sessionStorage.getItem('refreshToken');

    if (!accessToken && !refreshToken) {
        return;
    }

    if (accessToken && !isTokenExpired(accessToken)) {
        window.location.href = 'dashboard.html';
        return;
    }

    if (refreshToken) {
        const refreshed = await refreshAccessToken();
        if (refreshed) {
            window.location.href = 'dashboard.html';
            return;
        }
    }

    clearAuth();
}

// API Helper Functions
async function apiRequest(endpoint, options = {}) {
    const config = {
        headers: {
            'Content-Type': 'application/json',
            ...options.headers
        },
        ...options
    };

    // Add access token if available
    let accessToken = sessionStorage.getItem('accessToken');
    if (accessToken && isTokenExpired(accessToken)) {
        const refreshed = await refreshAccessToken();
        if (refreshed) {
            accessToken = sessionStorage.getItem('accessToken');
        }
    }

    if (accessToken) {
        config.headers['Authorization'] = `Bearer ${accessToken}`;
    }

    try {
        const response = await fetch(`${API_BASE_URL}${endpoint}`, config);
        const data = await response.json();

        if (!response.ok) {
            // Handle 401 - try to refresh token
            if (response.status === 401 && endpoint !== '/auth/refresh' && endpoint !== '/auth/login') {
                const refreshed = await refreshAccessToken();
                if (refreshed) {
                    // Retry original request with new token
                    return apiRequest(endpoint, options);
                } else {
                    // Refresh failed, redirect to login
                    logout();
                    throw new Error('Session expired. Please login again.');
                }
            }

            throw new Error(data.error?.message || 'Request failed');
        }

        return data;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

// Auth API
async function login(email, password) {
    const data = await apiRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password })
    });

    // Store tokens and user session in sessionStorage (cleared when browser tab/window is closed)
    sessionStorage.setItem('accessToken', data.accessToken);
    sessionStorage.setItem('refreshToken', data.refreshToken);
    sessionStorage.setItem('user', JSON.stringify(data.user));

    return data;
}

async function register(email, password) {
    return apiRequest('/auth/register', {
        method: 'POST',
        body: JSON.stringify({ email, password })
    });
}

async function refreshAccessToken() {
    const refreshToken = sessionStorage.getItem('refreshToken');
    if (!refreshToken) return false;

    try {
        const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ refreshToken })
        });

        if (!response.ok) {
            clearAuth();
            return false;
        }

        const data = await response.json();
        sessionStorage.setItem('accessToken', data.accessToken);
        if (data.refreshToken) {
            sessionStorage.setItem('refreshToken', data.refreshToken);
        }
        return true;
    } catch (error) {
        clearAuth();
        return false;
    }
}

async function logout() {
    const refreshToken = sessionStorage.getItem('refreshToken');

    try {
        if (refreshToken) {
            await apiRequest('/auth/logout', {
                method: 'POST',
                body: JSON.stringify({ refreshToken })
            });
        }
    } catch (error) {
        console.error('Logout error:', error);
    }

    // Clear session and local storage
    clearAuth();

    // Redirect to login
    window.location.href = 'index.html';
}

async function verifyEmail(token) {
    return apiRequest('/auth/verify-email', {
        method: 'POST',
        body: JSON.stringify({ token })
    });
}

async function forgotPassword(email) {
    return apiRequest('/auth/forgot-password', {
        method: 'POST',
        body: JSON.stringify({ email })
    });
}

async function resetPassword(token, newPassword) {
    return apiRequest('/auth/reset-password', {
        method: 'POST',
        body: JSON.stringify({ token, newPassword })
    });
}

async function changePassword(currentPassword, newPassword) {
    return apiRequest('/change-password', {
        method: 'POST',
        body: JSON.stringify({ currentPassword, newPassword })
    });
}

// User API
async function getSessions() {
    return apiRequest('/sessions');
}

async function revokeSession(sessionId) {
    return apiRequest(`/sessions/${sessionId}`, {
        method: 'DELETE'
    });
}

async function revokeAllSessions() {
    return apiRequest('/sessions', {
        method: 'DELETE'
    });
}

// User-Isolated Settings API
async function getUserSettings() {
    return apiRequest('/settings');
}

async function updateUserSettings(settings) {
    return apiRequest('/settings', {
        method: 'PUT',
        body: JSON.stringify(settings)
    });
}

// User-Isolated Jobs API (Job Tracker)
async function getJobs(status) {
    const query = status ? `?status=${encodeURIComponent(status)}` : '';
    return apiRequest(`/jobs${query}`);
}

async function createJob(jobData) {
    return apiRequest('/jobs', {
        method: 'POST',
        body: JSON.stringify(jobData)
    });
}

async function getJob(jobId) {
    return apiRequest(`/jobs/${jobId}`);
}

async function updateJob(jobId, jobData) {
    return apiRequest(`/jobs/${jobId}`, {
        method: 'PUT',
        body: JSON.stringify(jobData)
    });
}

async function deleteJob(jobId) {
    return apiRequest(`/jobs/${jobId}`, {
        method: 'DELETE'
    });
}

// User-Isolated Favorites API
async function getFavorites(type) {
    const query = type ? `?type=${encodeURIComponent(type)}` : '';
    return apiRequest(`/favorites${query}`);
}

async function addFavorite(favoriteData) {
    return apiRequest('/favorites', {
        method: 'POST',
        body: JSON.stringify(favoriteData)
    });
}

async function removeFavorite(favoriteId) {
    return apiRequest(`/favorites/${favoriteId}`, {
        method: 'DELETE'
    });
}

// User Profile & Nickname API
async function getProfile() {
    const data = await apiRequest('/me');
    if (data) {
        const currentUser = getCurrentUser() || {};
        const updated = { ...currentUser, ...data };
        sessionStorage.setItem('user', JSON.stringify(updated));
    }
    return data;
}

async function updateNickname(nickname) {
    const data = await apiRequest('/nickname', {
        method: 'PUT',
        body: JSON.stringify({ nickname })
    });
    if (data && data.user) {
        const currentUser = getCurrentUser() || {};
        currentUser.nickname = data.user.nickname;
        sessionStorage.setItem('user', JSON.stringify(currentUser));
    }
    return data;
}

// ============================================
// Zabum AI Assistant API Client
// ============================================

// Configurable Zabum AI Backend URL (Can be customized via localStorage or window.AI_API_URL)
let DEFAULT_AI_API_URL = window.AI_API_URL || localStorage.getItem('zabum_ai_api_url') || 'http://localhost:5001';

function getAiApiUrl() {
    return localStorage.getItem('zabum_ai_api_url') || DEFAULT_AI_API_URL;
}

function setAiApiUrl(url) {
    if (url) {
        localStorage.setItem('zabum_ai_api_url', url.trim().replace(/\/+$/, ''));
    } else {
        localStorage.removeItem('zabum_ai_api_url');
    }
}

async function aiApiRequest(endpoint, options = {}) {
    const token = getAccessToken();
    const baseUrl = getAiApiUrl();

    const headers = {
        'Content-Type': 'application/json',
        ...options.headers,
    };

    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    try {
        const response = await fetch(`${baseUrl}${endpoint}`, {
            ...options,
            headers,
        });

        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
            const errorMsg = data.error || `AI Request failed with status ${response.status}`;
            const err = new Error(errorMsg);
            err.status = response.status;
            err.code = data.code;
            throw err;
        }

        return data;
    } catch (error) {
        if (error.name === 'TypeError' && error.message.includes('fetch')) {
            const err = new Error('Zabum AI backend is offline. Ensure Flask server is running on ' + baseUrl);
            err.isOffline = true;
            throw err;
        }
        throw error;
    }
}

async function getAiStatus() {
    return aiApiRequest('/api/status');
}

async function sendChatMessage(message, conversationId = null) {
    return aiApiRequest('/api/chat', {
        method: 'POST',
        body: JSON.stringify({
            message,
            conversation_id: conversationId
        })
    });
}

async function getAiConversations() {
    return aiApiRequest('/api/conversations');
}

async function getAiConversation(convId) {
    return aiApiRequest(`/api/conversations/${convId}`);
}

async function createAiConversation(title = 'New Chat') {
    return aiApiRequest('/api/conversations', {
        method: 'POST',
        body: JSON.stringify({ title })
    });
}

async function updateAiConversation(convId, title) {
    return aiApiRequest(`/api/conversations/${convId}`, {
        method: 'PUT',
        body: JSON.stringify({ title })
    });
}

async function deleteAiConversation(convId) {
    return aiApiRequest(`/api/conversations/${convId}`, {
        method: 'DELETE'
    });
}

async function getAiMemories(category = null, search = null) {
    let query = '';
    const params = new URLSearchParams();
    if (category) params.append('category', category);
    if (search) params.append('q', search);
    if (params.toString()) query = `?${params.toString()}`;
    return aiApiRequest(`/api/memories${query}`);
}

async function deleteAiMemory(memId) {
    return aiApiRequest(`/api/memories/${memId}`, {
        method: 'DELETE'
    });
}




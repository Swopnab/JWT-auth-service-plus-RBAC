// API Configuration
const API_BASE_URL = 'https://auth-service-api.swopnabbikram.workers.dev';

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
    const accessToken = localStorage.getItem('accessToken');
    if (accessToken) {
        config.headers['Authorization'] = `Bearer ${accessToken}`;
    }

    try {
        const response = await fetch(`${API_BASE_URL}${endpoint}`, config);
        const data = await response.json();

        if (!response.ok) {
            // Handle 401 - try to refresh token
            if (response.status === 401 && endpoint !== '/auth/refresh') {
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

    // Store tokens
    localStorage.setItem('accessToken', data.accessToken);
    localStorage.setItem('refreshToken', data.refreshToken);
    localStorage.setItem('user', JSON.stringify(data.user));

    return data;
}

async function register(email, password) {
    return apiRequest('/auth/register', {
        method: 'POST',
        body: JSON.stringify({ email, password })
    });
}

async function refreshAccessToken() {
    const refreshToken = localStorage.getItem('refreshToken');
    if (!refreshToken) return false;

    try {
        const data = await apiRequest('/auth/refresh', {
            method: 'POST',
            body: JSON.stringify({ refreshToken })
        });

        localStorage.setItem('accessToken', data.accessToken);
        localStorage.setItem('refreshToken', data.refreshToken);
        return true;
    } catch (error) {
        return false;
    }
}

async function logout() {
    const refreshToken = localStorage.getItem('refreshToken');

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

    // Clear local storage
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('user');

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
    return apiRequest('/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({ currentPassword, newPassword })
    });
}

// User API
async function getSessions() {
    return apiRequest('/user/sessions');
}

async function revokeSession(sessionId) {
    return apiRequest(`/user/sessions/${sessionId}`, {
        method: 'DELETE'
    });
}

async function revokeAllSessions() {
    return apiRequest('/user/sessions', {
        method: 'DELETE'
    });
}

// Helper to check if user is logged in
function isLoggedIn() {
    return !!localStorage.getItem('accessToken');
}

// Helper to get current user
function getCurrentUser() {
    const userStr = localStorage.getItem('user');
    return userStr ? JSON.parse(userStr) : null;
}

// Protect pages that require authentication
function requireAuth() {
    if (!isLoggedIn()) {
        window.location.href = 'index.html';
    }
}

// Redirect if already logged in
function redirectIfLoggedIn() {
    if (isLoggedIn()) {
        window.location.href = 'dashboard.html';
    }
}

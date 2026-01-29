// Authentication API methods

import api from './api';
import type { LoginRequest, LoginResponse, RegisterRequest } from '../types';

export async function register(data: RegisterRequest): Promise<any> {
    const response = await api.post('/auth/register', data);
    return response.data;
}

export async function login(data: LoginRequest): Promise<LoginResponse> {
    const response = await api.post('/auth/login', data);
    return response.data;
}

export async function logout(refreshToken: string): Promise<void> {
    await api.post('/auth/logout', { refreshToken });
}

export async function refresh(refreshToken: string): Promise<{ accessToken: string; refreshToken: string }> {
    const response = await api.post('/auth/refresh', { refreshToken });
    return response.data;
}

export async function verifyEmail(token: string): Promise<void> {
    await api.post('/auth/verify-email', { token });
}

export async function forgotPassword(email: string): Promise<any> {
    const response = await api.post('/auth/forgot-password', { email });
    return response.data;
}

export async function resetPassword(token: string, newPassword: string): Promise<void> {
    await api.post('/auth/reset-password', { token, newPassword });
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await api.post('/auth/change-password', { currentPassword, newPassword });
}

export async function getMe(): Promise<any> {
    const response = await api.get('/me');
    return response.data;
}

export async function getSessions(): Promise<any> {
    const response = await api.get('/sessions');
    return response.data;
}

export async function revokeSession(sessionId: string): Promise<void> {
    await api.delete(`/sessions/${sessionId}`);
}

export async function revokeAllSessions(): Promise<void> {
    await api.delete('/sessions/revoke-all');
}

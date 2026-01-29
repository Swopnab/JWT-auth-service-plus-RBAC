// Zustand store for authentication state

import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { User } from '../types';
import * as authApi from '../services/auth.api';

interface AuthState {
    user: User | null;
    accessToken: string | null;
    refreshToken: string | null;
    isAuthenticated: boolean;

    // Actions
    login: (email: string, password: string) => Promise<void>;
    register: (email: string, password: string) => Promise<void>;
    logout: () => Promise<void>;
    refreshAccessToken: () => Promise<void>;
    setTokens: (accessToken: string, refreshToken: string) => void;
    setUser: (user: User) => void;
    clearAuth: () => void;
}

export const useAuthStore = create<AuthState>()(
    persist(
        (set, get) => ({
            user: null,
            accessToken: null,
            refreshToken: null,
            isAuthenticated: false,

            login: async (email: string, password: string) => {
                const response = await authApi.login({ email, password });

                set({
                    user: response.user,
                    accessToken: response.accessToken,
                    refreshToken: response.refreshToken,
                    isAuthenticated: true,
                });
            },

            register: async (email: string, password: string) => {
                await authApi.register({ email, password });
            },

            logout: async () => {
                const { refreshToken } = get();

                if (refreshToken) {
                    try {
                        await authApi.logout(refreshToken);
                    } catch (error) {
                        console.error('Logout error:', error);
                    }
                }

                get().clearAuth();
            },

            refreshAccessToken: async () => {
                const { refreshToken } = get();

                if (!refreshToken) {
                    throw new Error('No refresh token available');
                }

                try {
                    const response = await authApi.refresh(refreshToken);

                    set({
                        accessToken: response.accessToken,
                        refreshToken: response.refreshToken,
                    });
                } catch (error) {
                    // Refresh failed - clear auth state
                    get().clearAuth();
                    throw error;
                }
            },

            setTokens: (accessToken: string, refreshToken: string) => {
                set({ accessToken, refreshToken, isAuthenticated: true });
            },

            setUser: (user: User) => {
                set({ user, isAuthenticated: true });
            },

            clearAuth: () => {
                set({
                    user: null,
                    accessToken: null,
                    refreshToken: null,
                    isAuthenticated: false,
                });
            },
        }),
        {
            name: 'auth-storage',
            partialize: (state) => ({
                refreshToken: state.refreshToken, // Only persist refresh token
                user: state.user,
            }),
        }
    )
);

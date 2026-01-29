// Main Cloudflare Worker entry point

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import type { Env } from './types';
import { formatErrorResponse } from './utils/errors';
import auth from './routes/auth';
import user from './routes/user';
import admin from './routes/admin';

const app = new Hono<{ Bindings: Env }>();

// CORS middleware
app.use('/*', async (c, next) => {
    const corsMiddleware = cors({
        origin: [c.env.FRONTEND_URL, 'http://localhost:5173'],
        allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        allowHeaders: ['Content-Type', 'Authorization'],
        exposeHeaders: ['Content-Length', 'X-Request-Id'],
        maxAge: 86400,
        credentials: true,
    });

    return corsMiddleware(c, next);
});

// Health check
app.get('/health', (c) => {
    return c.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Mount routes
app.route('/auth', auth);
app.route('/', user); // /me, /sessions
app.route('/admin', admin);

// 404 handler
app.notFound((c) => {
    return c.json({ error: { message: 'Not found', code: 'NOT_FOUND' } }, 404);
});

// Global error handler
app.onError((err, c) => {
    console.error('Error:', err);

    const statusCode = (err as any).statusCode || 500;
    const response = formatErrorResponse(err);

    return c.json(response, statusCode);
});

export default app;

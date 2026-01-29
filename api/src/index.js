// Main Cloudflare Worker entry point (Vanilla JavaScript)

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { formatErrorResponse } from './utils/errors.js';
import auth from './routes/auth.js';
import user from './routes/user.js';
import admin from './routes/admin.js';

const app = new Hono();

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

    const statusCode = err.statusCode || 500;
    const response = formatErrorResponse(err);

    return c.json(response, statusCode);
});

export default app;

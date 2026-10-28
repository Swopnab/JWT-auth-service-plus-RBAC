// Main Cloudflare Worker entry point (Vanilla JavaScript)

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { formatErrorResponse } from './utils/errors.js';
import auth from './routes/auth.js';
import user from './routes/user.js';
import admin from './routes/admin.js';
import jobs from './routes/jobs.js';
import favorites from './routes/favorites.js';

const app = new Hono();

// CORS middleware
app.use('/*', async (c, next) => {
    const corsMiddleware = cors({
        origin: [
            'https://swopnab.github.io',
            c.env.FRONTEND_URL,
            'http://localhost:5173'
        ],
        allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        allowHeaders: ['Content-Type', 'Authorization'],
        exposeHeaders: ['Content-Length', 'X-Request-Id'],
        maxAge: 86400,
        credentials: true,
    });

    return corsMiddleware(c, next);
});

// Reject non-object JSON before route destructuring. Parsing is cached by Hono.
app.use('/*', async (c, next) => {
    if (['POST','PUT','PATCH'].includes(c.req.method) && (c.req.header('Content-Type') || '').includes('application/json')) {
        const body = await c.req.json();
        if (!body || typeof body !== 'object' || Array.isArray(body)) return c.json({error:{message:'Send a JSON object',code:'VALIDATION_ERROR'}},400);
    }
    await next();
});

// Health check
app.get('/health', (c) => {
    return c.json({ status: 'healthy', review_fixture: c.env.REVIEW_FIXTURE === '1', timestamp: new Date().toISOString() });
});

// Mount routes
app.route('/auth', auth);
app.route('/user', user);
app.route('/jobs', jobs);
app.route('/favorites', favorites);
app.route('/', user); // /me, /sessions, /settings fallback
app.route('/admin', admin);

// 404 handler
app.notFound((c) => {
    return c.json({ error: { message: 'Not found', code: 'NOT_FOUND' } }, 404);
});

// Global error handler
app.onError((err, c) => {
    if (!(err instanceof SyntaxError) && (!err.statusCode || err.statusCode >= 500)) console.error('Error:', err);

    const statusCode = err instanceof SyntaxError ? 400 : (err.statusCode || 500);
    const response = err instanceof SyntaxError ? {error:{message:'Send valid JSON',code:'VALIDATION_ERROR'}} : formatErrorResponse(err);

    return c.json(response, statusCode);
});

export default app;

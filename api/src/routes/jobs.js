// User-Isolated Jobs API Routes
import { Hono } from 'hono';
import { authMiddleware, getAuthContext } from '../middleware/auth.js';
import { ValidationError, NotFoundError } from '../utils/errors.js';

const jobs = new Hono();

// Apply authMiddleware to all jobs routes
jobs.use('*', authMiddleware);

// GET /jobs - List all jobs belonging to the authenticated user
jobs.get('/', async (c) => {
    const { user } = getAuthContext(c);

    const statusFilter = c.req.query('status');
    let query = 'SELECT * FROM jobs WHERE user_id = ?';
    const params = [user.id];

    if (statusFilter) {
        query += ' AND status = ?';
        params.push(statusFilter);
    }

    query += ' ORDER BY created_at DESC';

    const result = await c.env.DB.prepare(query).bind(...params).all();
    return c.json({ jobs: result.results || [] });
});

// POST /jobs - Create a new job record for the authenticated user
jobs.post('/', async (c) => {
    const { user } = getAuthContext(c);
    const body = await c.req.json();
    const { company, position, status, salary, location, job_url, notes } = body;

    if (!company || !company.trim()) {
        throw new ValidationError('Company name is required');
    }
    if (!position || !position.trim()) {
        throw new ValidationError('Position title is required');
    }

    const jobStatus = status || 'Applied';

    // Insert record strictly using user.id from verified JWT
    const insertResult = await c.env.DB.prepare(
        `INSERT INTO jobs (user_id, company, position, status, salary, location, job_url, notes, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))`
    ).bind(
        user.id,
        company.trim(),
        position.trim(),
        jobStatus,
        salary || null,
        location || null,
        job_url || null,
        notes || null
    ).run();

    const newJobId = insertResult.meta?.last_row_id;
    const createdJob = await c.env.DB.prepare('SELECT * FROM jobs WHERE id = ? AND user_id = ?')
        .bind(newJobId, user.id)
        .first();

    return c.json({ message: 'Job created successfully', job: createdJob }, 201);
});

// GET /jobs/:id - Get a specific job owned by the authenticated user
jobs.get('/:id', async (c) => {
    const { user } = getAuthContext(c);
    const jobId = parseInt(c.req.param('id'));

    if (isNaN(jobId)) {
        throw new ValidationError('Invalid job ID');
    }

    // Ownership check: must match both record ID and user_id
    const job = await c.env.DB.prepare('SELECT * FROM jobs WHERE id = ? AND user_id = ?')
        .bind(jobId, user.id)
        .first();

    if (!job) {
        throw new NotFoundError('Job not found');
    }

    return c.json({ job });
});

// PUT /jobs/:id - Update a job owned by the authenticated user
jobs.put('/:id', async (c) => {
    const { user } = getAuthContext(c);
    const jobId = parseInt(c.req.param('id'));

    if (isNaN(jobId)) {
        throw new ValidationError('Invalid job ID');
    }

    const body = await c.req.json();
    const { company, position, status, salary, location, job_url, notes } = body;

    // Verify ownership first
    const existing = await c.env.DB.prepare('SELECT id FROM jobs WHERE id = ? AND user_id = ?')
        .bind(jobId, user.id)
        .first();

    if (!existing) {
        throw new NotFoundError('Job not found');
    }

    if (!company || !company.trim()) {
        throw new ValidationError('Company name is required');
    }
    if (!position || !position.trim()) {
        throw new ValidationError('Position title is required');
    }

    await c.env.DB.prepare(
        `UPDATE jobs 
         SET company = ?, position = ?, status = ?, salary = ?, location = ?, job_url = ?, notes = ?, updated_at = datetime('now')
         WHERE id = ? AND user_id = ?`
    ).bind(
        company.trim(),
        position.trim(),
        status || 'Applied',
        salary || null,
        location || null,
        job_url || null,
        notes || null,
        jobId,
        user.id
    ).run();

    const updatedJob = await c.env.DB.prepare('SELECT * FROM jobs WHERE id = ? AND user_id = ?')
        .bind(jobId, user.id)
        .first();

    return c.json({ message: 'Job updated successfully', job: updatedJob });
});

// DELETE /jobs/:id - Delete a job owned by the authenticated user
jobs.delete('/:id', async (c) => {
    const { user } = getAuthContext(c);
    const jobId = parseInt(c.req.param('id'));

    if (isNaN(jobId)) {
        throw new ValidationError('Invalid job ID');
    }

    // Verify ownership and delete in a single query
    const deleteResult = await c.env.DB.prepare('DELETE FROM jobs WHERE id = ? AND user_id = ?')
        .bind(jobId, user.id)
        .run();

    if (deleteResult.meta?.changes === 0) {
        throw new NotFoundError('Job not found');
    }

    return c.json({ message: 'Job deleted successfully' });
});

export default jobs;

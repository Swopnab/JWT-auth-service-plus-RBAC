// User-Isolated Favorites API Routes
import { Hono } from 'hono';
import { authMiddleware, getAuthContext } from '../middleware/auth.js';
import { ValidationError, NotFoundError, ConflictError } from '../utils/errors.js';

const favorites = new Hono();

// Apply authMiddleware to all favorites routes
favorites.use('*', authMiddleware);

// GET /favorites - List all favorites for authenticated user
favorites.get('/', async (c) => {
    const { user } = getAuthContext(c);
    const itemType = c.req.query('type');

    let query = 'SELECT * FROM user_favorites WHERE user_id = ?';
    const params = [user.id];

    if (itemType) {
        query += ' AND item_type = ?';
        params.push(itemType);
    }

    query += ' ORDER BY created_at DESC';

    const result = await c.env.DB.prepare(query).bind(...params).all();
    return c.json({ favorites: result.results || [] });
});

// POST /favorites - Add a new favorite for authenticated user
favorites.post('/', async (c) => {
    const { user } = getAuthContext(c);
    const body = await c.req.json();
    const { item_type, item_id, title, artist, artwork_url, stream_url, duration } = body;

    if (!item_id) {
        throw new ValidationError('Item ID is required');
    }
    if (!title) {
        throw new ValidationError('Title is required');
    }

    const type = item_type || 'track';

    try {
        const insertResult = await c.env.DB.prepare(
            `INSERT INTO user_favorites (user_id, item_type, item_id, title, artist, artwork_url, stream_url, duration, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
        ).bind(
            user.id,
            type,
            String(item_id),
            title,
            artist || null,
            artwork_url || null,
            stream_url || null,
            duration || null
        ).run();

        const created = await c.env.DB.prepare('SELECT * FROM user_favorites WHERE id = ? AND user_id = ?')
            .bind(insertResult.meta?.last_row_id, user.id)
            .first();

        return c.json({ message: 'Favorite saved', favorite: created }, 201);
    } catch (err) {
        if (err.message && err.message.includes('UNIQUE')) {
            throw new ConflictError('Item is already in your favorites');
        }
        throw err;
    }
});

// DELETE /favorites/:id - Remove a favorite owned by authenticated user
favorites.delete('/:id', async (c) => {
    const { user } = getAuthContext(c);
    const favoriteId = parseInt(c.req.param('id'));

    let deleteResult;
    if (isNaN(favoriteId)) {
        // Allow deleting by item_id directly
        const itemId = c.req.param('id');
        deleteResult = await c.env.DB.prepare('DELETE FROM user_favorites WHERE item_id = ? AND user_id = ?')
            .bind(itemId, user.id)
            .run();
    } else {
        deleteResult = await c.env.DB.prepare('DELETE FROM user_favorites WHERE (id = ? OR item_id = ?) AND user_id = ?')
            .bind(favoriteId, String(favoriteId), user.id)
            .run();
    }

    if (deleteResult.meta?.changes === 0) {
        throw new NotFoundError('Favorite not found');
    }

    return c.json({ message: 'Favorite removed successfully' });
});

export default favorites;

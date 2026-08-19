// Audius Music API Service
const AUDIUS_APP_NAME = 'AuthServiceMusicPlayer';
const AUDIUS_DEFAULT_HOST = 'https://api.audius.co';

let selectedHost = AUDIUS_DEFAULT_HOST;

/**
 * Initialize and discover the fastest active Audius host
 */
async function initAudiusHost() {
    try {
        const res = await fetch('https://api.audius.co', { cache: 'no-cache' });
        if (res.ok) {
            const json = await res.json();
            if (json.data && json.data.length > 0) {
                selectedHost = json.data[Math.floor(Math.random() * json.data.length)];
            }
        }
    } catch (e) {
        console.warn('Using default Audius host fallback:', AUDIUS_DEFAULT_HOST);
        selectedHost = AUDIUS_DEFAULT_HOST;
    }
}

/**
 * Normalize an Audius track object into standard player format
 * @param {object} track
 * @returns {object}
 */
function normalizeTrack(track) {
    if (!track) return null;

    // Extract best artwork thumbnail
    let artworkUrl = null;
    if (track.artwork) {
        artworkUrl = track.artwork['480x480'] || track.artwork['150x150'] || track.artwork['1000x1000'] || null;
    }

    const artistName = (track.user && (track.user.name || track.user.handle)) ? (track.user.name || track.user.handle) : 'Unknown Artist';

    const trackId = track.id || track.track_id;
    const streamUrl = `${selectedHost}/v1/tracks/${trackId}/stream?app_name=${AUDIUS_APP_NAME}`;

    return {
        id: trackId,
        title: track.title || 'Untitled Track',
        artist: artistName,
        duration: track.duration || 0,
        artworkUrl: artworkUrl,
        streamUrl: streamUrl,
        genre: track.genre || '',
        permalink: track.permalink || ''
    };
}

/**
 * Fetch top trending tracks on Audius
 * @param {number} [limit=25]
 * @returns {Promise<Array>}
 */
async function getTrendingTracks(limit = 25) {
    try {
        const url = `${selectedHost}/v1/tracks/trending?app_name=${AUDIUS_APP_NAME}&limit=${limit}`;
        const res = await fetch(url);
        if (!res.ok) {
            throw new Error(`Audius API error: ${res.status}`);
        }
        const json = await res.json();
        const tracks = (json.data || []).map(normalizeTrack).filter(Boolean);
        return tracks;
    } catch (err) {
        console.error('Failed to fetch trending tracks from Audius:', err);
        throw err;
    }
}

/**
 * Search tracks and artists on Audius
 * @param {string} query
 * @param {number} [limit=25]
 * @returns {Promise<Array>}
 */
async function searchTracks(query, limit = 25) {
    if (!query || !query.trim()) {
        return getTrendingTracks(limit);
    }

    try {
        const encoded = encodeURIComponent(query.trim());
        const url = `${selectedHost}/v1/tracks/search?query=${encoded}&app_name=${AUDIUS_APP_NAME}&limit=${limit}`;
        const res = await fetch(url);
        if (!res.ok) {
            throw new Error(`Audius search error: ${res.status}`);
        }
        const json = await res.json();
        const tracks = (json.data || []).map(normalizeTrack).filter(Boolean);
        return tracks;
    } catch (err) {
        console.error('Failed to search tracks on Audius:', err);
        throw err;
    }
}

// Export functions to global scope for client consumption
window.AudiusService = {
    init: initAudiusHost,
    getTrendingTracks,
    searchTracks,
    normalizeTrack
};

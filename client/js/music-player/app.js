// Music Player Application Logic with Audius Streaming API
const audioPlayer = document.getElementById('audioPlayer');
const playBtn = document.getElementById('playBtn');
const prevBtn = document.getElementById('prevBtn');
const nextBtn = document.getElementById('nextBtn');
const songList = document.getElementById('songList');
const searchInput = document.getElementById('searchInput');
const searchClearBtn = document.getElementById('searchClearBtn');
const playlistTitle = document.getElementById('playlistTitle');
const playlistCount = document.getElementById('playlistCount');

const currentTitle = document.getElementById('currentTitle');
const currentArtist = document.getElementById('currentArtist');
const currentTitleLarge = document.getElementById('currentTitleLarge');
const currentArtistLarge = document.getElementById('currentArtistLarge');
const albumArtLarge = document.getElementById('albumArtLarge');
const playerArtwork = document.getElementById('playerArtwork');

const progressBar = document.getElementById('progressBar');
const currentTimeEl = document.getElementById('currentTime');
const durationEl = document.getElementById('duration');
const volumeBar = document.getElementById('volumeBar');
const volumeValueEl = document.getElementById('volumeValue');

let playlist = [];
let currentSongIndex = -1;
let isPlaying = false;
let searchDebounceTimer = null;

// Format time (seconds -> MM:SS)
function formatTime(seconds) {
    if (isNaN(seconds) || seconds < 0) return '0:00';
    const min = Math.floor(seconds / 60);
    const sec = Math.floor(seconds % 60);
    return `${min}:${sec < 10 ? '0' + sec : sec}`;
}

// Show Toast Notification
function showPlayerToast(msg, type = 'info') {
    if (typeof showToast === 'function') {
        showToast(msg, type);
    } else {
        console.log(`[${type.toUpperCase()}] ${msg}`);
    }
}

// Update slider visual fill
function updateSliderFill(slider) {
    if (!slider) return;
    const min = Number(slider.min) || 0;
    const max = Number(slider.max) || 100;
    const val = ((slider.value - min) / (max - min)) * 100;
    slider.style.backgroundSize = `${val}% 100%`;
}

// Render Song List / Search Results
function renderSongList(tracks, headerTitle = 'Trending Tracks') {
    playlist = tracks || [];
    if (playlistTitle) playlistTitle.textContent = headerTitle;
    if (playlistCount) playlistCount.textContent = playlist.length > 0 ? `(${playlist.length})` : '';

    if (!songList) return;
    songList.innerHTML = '';

    if (playlist.length === 0) {
        songList.innerHTML = `
            <div class="state-message">
                <i class="fa-solid fa-compact-disc"></i>
                <p>No tracks found. Try another search query.</p>
            </div>
        `;
        return;
    }

    playlist.forEach((track, index) => {
        const li = document.createElement('li');
        li.className = 'song-item' + (index === currentSongIndex ? ' active' : '');

        const artworkHtml = track.artworkUrl
            ? `<div class="song-thumb"><img src="${track.artworkUrl}" alt="" loading="lazy" onerror="this.parentElement.innerHTML='<i class=\\\'fa-solid fa-music\\\'></i>'"></div>`
            : `<div class="song-thumb"><i class="fa-solid fa-music"></i></div>`;

        li.innerHTML = `
            ${artworkHtml}
            <div class="song-info">
                <div class="song-title">${escapeHtml(track.title)}</div>
                <div class="song-artist">${escapeHtml(track.artist)}</div>
            </div>
            <div class="song-duration">${formatTime(track.duration)}</div>
        `;

        li.addEventListener('click', () => {
            currentSongIndex = index;
            loadAndPlayTrack(currentSongIndex);
        });

        songList.appendChild(li);
    });
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Show list loading state
function showListLoading(message = 'Searching Audius...') {
    if (!songList) return;
    songList.innerHTML = `
        <div class="state-message">
            <div class="spinner-small"></div>
            <p>${message}</p>
        </div>
    `;
}

// Show list error state
function showListError(message = 'Failed to load tracks. Please try again.') {
    if (!songList) return;
    songList.innerHTML = `
        <div class="state-message">
            <i class="fa-solid fa-triangle-exclamation" style="color: var(--accent-color);"></i>
            <p>${message}</p>
            <button onclick="loadTrendingTracks()" style="background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.2); color: white; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 0.8rem; margin-top: 6px;">Load Trending</button>
        </div>
    `;
}

// Load and play track
function loadAndPlayTrack(index) {
    if (index < 0 || index >= playlist.length) return;
    const track = playlist[index];

    // Update active class in list
    const items = songList.querySelectorAll('.song-item');
    items.forEach((item, i) => {
        if (i === index) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });

    // Update Player Info
    if (currentTitle) currentTitle.textContent = track.title;
    if (currentArtist) currentArtist.textContent = track.artist;
    if (currentTitleLarge) currentTitleLarge.textContent = track.title;
    if (currentArtistLarge) currentArtistLarge.textContent = track.artist;

    // Update Large Artwork
    if (albumArtLarge) {
        if (track.artworkUrl) {
            albumArtLarge.innerHTML = `<img src="${track.artworkUrl}" alt="${escapeHtml(track.title)}" onerror="this.parentElement.innerHTML='<i class=\\\'fa-solid fa-compact-disc\\\'></i>'">`;
        } else {
            albumArtLarge.innerHTML = `<i class="fa-solid fa-compact-disc"></i>`;
        }
    }

    // Update Player Bar Artwork
    if (playerArtwork) {
        if (track.artworkUrl) {
            playerArtwork.innerHTML = `<img src="${track.artworkUrl}" alt="" onerror="this.parentElement.innerHTML='<i class=\\\'fa-solid fa-music\\\'></i>'">`;
        } else {
            playerArtwork.innerHTML = `<i class="fa-solid fa-music"></i>`;
        }
    }

    // Set Audio Source and Play
    audioPlayer.src = track.streamUrl;
    audioPlayer.load();

    const playPromise = audioPlayer.play();
    if (playPromise !== undefined) {
        playPromise
            .then(() => {
                isPlaying = true;
                updatePlayButton();
            })
            .catch(err => {
                console.warn('Audio play auto-start prevented or stream failed:', err);
                isPlaying = false;
                updatePlayButton();
            });
    }
}

function updatePlayButton() {
    if (!playBtn) return;
    if (isPlaying) {
        playBtn.innerHTML = '<i class="fa-solid fa-pause"></i>';
    } else {
        playBtn.innerHTML = '<i class="fa-solid fa-play"></i>';
    }
}

function togglePlay() {
    if (playlist.length === 0) return;

    if (currentSongIndex === -1) {
        currentSongIndex = 0;
        loadAndPlayTrack(0);
        return;
    }

    if (audioPlayer.paused) {
        audioPlayer.play().then(() => {
            isPlaying = true;
            updatePlayButton();
        }).catch(err => {
            console.error('Play error:', err);
        });
    } else {
        audioPlayer.pause();
        isPlaying = false;
        updatePlayButton();
    }
}

function playNext() {
    if (playlist.length === 0) return;
    currentSongIndex++;
    if (currentSongIndex >= playlist.length) {
        currentSongIndex = 0;
    }
    loadAndPlayTrack(currentSongIndex);
}

function playPrev() {
    if (playlist.length === 0) return;
    currentSongIndex--;
    if (currentSongIndex < 0) {
        currentSongIndex = playlist.length - 1;
    }
    loadAndPlayTrack(currentSongIndex);
}

// Audio Player Event Listeners
audioPlayer.addEventListener('play', () => {
    isPlaying = true;
    updatePlayButton();
});

audioPlayer.addEventListener('pause', () => {
    isPlaying = false;
    updatePlayButton();
});

audioPlayer.addEventListener('timeupdate', (e) => {
    const { duration, currentTime } = audioPlayer;
    if (duration && !isNaN(duration)) {
        const progressPercent = (currentTime / duration) * 100;
        progressBar.value = progressPercent;
        updateSliderFill(progressBar);

        if (currentTimeEl) currentTimeEl.textContent = formatTime(currentTime);
        if (durationEl) durationEl.textContent = formatTime(duration);
    }
});

audioPlayer.addEventListener('ended', () => {
    playNext();
});

audioPlayer.addEventListener('error', (e) => {
    console.error('Audio playback error:', e);
    showPlayerToast('Track stream unavailable. Skipping to next...', 'error');
    setTimeout(() => {
        if (playlist.length > 1) {
            playNext();
        }
    }, 1200);
});

// Controls Event Listeners
if (playBtn) playBtn.addEventListener('click', togglePlay);
if (nextBtn) nextBtn.addEventListener('click', playNext);
if (prevBtn) prevBtn.addEventListener('click', playPrev);

if (progressBar) {
    progressBar.addEventListener('input', () => {
        const duration = audioPlayer.duration;
        if (duration && !isNaN(duration)) {
            audioPlayer.currentTime = (progressBar.value * duration) / 100;
        }
        updateSliderFill(progressBar);
    });
}

if (volumeBar) {
    volumeBar.addEventListener('input', (e) => {
        const value = e.target.value;
        audioPlayer.volume = value / 100;
        if (volumeValueEl) volumeValueEl.textContent = value;
        updateSliderFill(volumeBar);
    });
    updateSliderFill(volumeBar);
}

// Search Functionality
async function performSearch(query) {
    if (!query || !query.trim()) {
        loadTrendingTracks();
        return;
    }

    if (searchClearBtn) searchClearBtn.classList.remove('hidden');
    showListLoading(`Searching for "${query}"...`);

    try {
        const tracks = await window.AudiusService.searchTracks(query);
        renderSongList(tracks, `Results for "${query}"`);
    } catch (err) {
        showListError('Failed to search tracks. Please check your network connection.');
    }
}

async function loadTrendingTracks() {
    if (searchClearBtn) searchClearBtn.classList.add('hidden');
    if (searchInput) searchInput.value = '';
    showListLoading('Loading trending tracks...');

    try {
        const tracks = await window.AudiusService.getTrendingTracks(25);
        renderSongList(tracks, 'Trending Tracks');
    } catch (err) {
        showListError('Unable to load tracks from Audius API.');
    }
}

if (searchInput) {
    searchInput.addEventListener('input', (e) => {
        const query = e.target.value;
        if (searchClearBtn) {
            if (query) {
                searchClearBtn.classList.remove('hidden');
            } else {
                searchClearBtn.classList.add('hidden');
            }
        }

        clearTimeout(searchDebounceTimer);
        searchDebounceTimer = setTimeout(() => {
            performSearch(query);
        }, 350);
    });

    searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            clearTimeout(searchDebounceTimer);
            performSearch(searchInput.value);
        }
    });
}

if (searchClearBtn) {
    searchClearBtn.addEventListener('click', () => {
        searchInput.value = '';
        loadTrendingTracks();
    });
}

// Global initialization function called after requireAuth() passes
window.initMusicPlayer = async function () {
    try {
        if (window.AudiusService && typeof window.AudiusService.init === 'function') {
            await window.AudiusService.init();
        }
        await loadTrendingTracks();
    } catch (err) {
        console.error('Error initializing music player:', err);
    }
};

window.loadTrendingTracks = loadTrendingTracks;

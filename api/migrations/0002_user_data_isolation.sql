-- Migration: 0002_user_data_isolation.sql
-- Description: Add user-isolated data tables for Jobs, Favorites, and User Settings with user_id ownership

-- 1. Jobs table (isolated per user for Job Tracker)
CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  company TEXT NOT NULL,
  position TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Applied',
  salary TEXT,
  location TEXT,
  job_url TEXT,
  notes TEXT,
  applied_at TEXT DEFAULT (datetime('now')),
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_jobs_user_id ON jobs(user_id);
CREATE INDEX IF NOT EXISTS idx_jobs_user_id_status ON jobs(user_id, status);

-- 2. User Favorites / Saved items table (isolated per user)
CREATE TABLE IF NOT EXISTS user_favorites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  item_type TEXT NOT NULL, -- 'track', 'playlist', 'game_score'
  item_id TEXT NOT NULL,
  title TEXT NOT NULL,
  artist TEXT,
  artwork_url TEXT,
  stream_url TEXT,
  duration INTEGER,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(user_id, item_type, item_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_favorites_user_id ON user_favorites(user_id);

-- 3. User Settings table (isolated per user)
CREATE TABLE IF NOT EXISTS user_settings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL UNIQUE,
  theme TEXT DEFAULT 'dark',
  notifications_enabled INTEGER DEFAULT 1,
  dashboard_layout TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_settings_user_id ON user_settings(user_id);

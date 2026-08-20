"""
Database Initialization and Connection Management for Zabum AI
User-isolated tables with SQLite WAL mode
"""

import sqlite3
from pathlib import Path
from config import DB_PATH

def get_db_connection() -> sqlite3.Connection:
    """Create and return a new SQLite database connection with row factory"""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn

def init_db():
    """Initialize SQLite database tables with strict per-user scoping and indexes"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Conversations Table (Isolated per user_id)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS conversations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL DEFAULT 'New Chat',
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_conversations_user ON conversations(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_conversations_updated ON conversations(user_id, updated_at DESC);")

    # 2. Messages Table (Isolated per conversation and user_id)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        conversation_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        role TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_messages_conv_user ON messages(conversation_id, user_id);")

    # 3. Memories Table (Isolated per user_id)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS memories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'general',
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_memories_user ON memories(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_memories_user_cat ON memories(user_id, category);")

    conn.commit()
    conn.close()

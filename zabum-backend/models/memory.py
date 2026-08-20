"""
Memory Model for Zabum AI with Strict User Scoping
"""

from typing import Optional
from models.database import get_db_connection

class MemoryModel:
    @staticmethod
    def get_all(user_id: int, category: Optional[str] = None, search: Optional[str] = None) -> list[dict]:
        """Fetch all memories for a user, optionally filtered by category or search query"""
        conn = get_db_connection()
        cursor = conn.cursor()

        query = "SELECT * FROM memories WHERE user_id = ?"
        params = [user_id]

        if category:
            query += " AND category = ?"
            params.append(category)

        if search:
            query += " AND content LIKE ?"
            params.append(f"%{search}%")

        query += " ORDER BY updated_at DESC"

        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    @staticmethod
    def get_by_id(mem_id: int, user_id: int) -> Optional[dict]:
        """Get single memory by ID for specified user"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM memories WHERE id = ? AND user_id = ?",
            (mem_id, user_id)
        )
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    @staticmethod
    def create(user_id: int, content: str, category: str = "general") -> dict:
        """Create new memory bound to user_id"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO memories (user_id, content, category) VALUES (?, ?, ?)",
            (user_id, content, category)
        )
        mem_id = cursor.lastrowid
        conn.commit()
        cursor.execute("SELECT * FROM memories WHERE id = ?", (mem_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row)

    @staticmethod
    def update(mem_id: int, user_id: int, content: str, category: Optional[str] = None) -> Optional[dict]:
        """Update memory with ownership check"""
        conn = get_db_connection()
        cursor = conn.cursor()

        if category:
            cursor.execute(
                "UPDATE memories SET content = ?, category = ?, updated_at = datetime('now') WHERE id = ? AND user_id = ?",
                (content, category, mem_id, user_id)
            )
        else:
            cursor.execute(
                "UPDATE memories SET content = ?, updated_at = datetime('now') WHERE id = ? AND user_id = ?",
                (content, mem_id, user_id)
            )
        conn.commit()
        cursor.execute("SELECT * FROM memories WHERE id = ? AND user_id = ?", (mem_id, user_id))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    @staticmethod
    def delete(mem_id: int, user_id: int) -> bool:
        """Delete memory with ownership check"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM memories WHERE id = ? AND user_id = ?",
            (mem_id, user_id)
        )
        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return deleted

    @staticmethod
    def exists_similar(user_id: int, content: str) -> bool:
        """Check if user already has an identical/similar memory"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) as count FROM memories WHERE user_id = ? AND LOWER(content) = LOWER(?)",
            (user_id, content.strip())
        )
        row = cursor.fetchone()
        conn.close()
        return (row["count"] if row else 0) > 0

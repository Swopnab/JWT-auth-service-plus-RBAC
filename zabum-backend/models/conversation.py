"""
Conversation and Message Database Models with Strict User Scoping
"""

from typing import Optional
from models.database import get_db_connection

class ConversationModel:
    @staticmethod
    def get_all(user_id: int) -> list[dict]:
        """Fetch all conversations owned by user_id ordered by latest updated"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM conversations WHERE user_id = ? ORDER BY updated_at DESC",
            (user_id,)
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    @staticmethod
    def get_by_id(conv_id: int, user_id: int) -> Optional[dict]:
        """Fetch conversation by ID, strictly enforcing user ownership"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM conversations WHERE id = ? AND user_id = ?",
            (conv_id, user_id)
        )
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    @staticmethod
    def create(user_id: int, title: str = "New Chat") -> dict:
        """Create new conversation bound to user_id"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO conversations (user_id, title) VALUES (?, ?)",
            (user_id, title)
        )
        conv_id = cursor.lastrowid
        conn.commit()
        cursor.execute("SELECT * FROM conversations WHERE id = ?", (conv_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row)

    @staticmethod
    def update_title(conv_id: int, user_id: int, title: str) -> Optional[dict]:
        """Update conversation title with user ownership check"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE conversations SET title = ?, updated_at = datetime('now') WHERE id = ? AND user_id = ?",
            (title, conv_id, user_id)
        )
        conn.commit()
        cursor.execute("SELECT * FROM conversations WHERE id = ? AND user_id = ?", (conv_id, user_id))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    @staticmethod
    def touch(conv_id: int, user_id: int) -> None:
        """Update updated_at timestamp on conversation"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE conversations SET updated_at = datetime('now') WHERE id = ? AND user_id = ?",
            (conv_id, user_id)
        )
        conn.commit()
        conn.close()

    @staticmethod
    def delete(conv_id: int, user_id: int) -> bool:
        """Delete conversation and cascade messages with user ownership check"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM conversations WHERE id = ? AND user_id = ?",
            (conv_id, user_id)
        )
        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return deleted


class MessageModel:
    @staticmethod
    def get_by_conversation(conv_id: int, user_id: int, limit: Optional[int] = None) -> list[dict]:
        """Fetch messages in conversation, strictly verifying user ownership via join"""
        conn = get_db_connection()
        cursor = conn.cursor()
        if limit:
            cursor.execute(
                """
                SELECT m.* FROM messages m
                JOIN conversations c ON m.conversation_id = c.id
                WHERE m.conversation_id = ? AND c.user_id = ?
                ORDER BY m.id DESC LIMIT ?
                """,
                (conv_id, user_id, limit)
            )
            rows = cursor.fetchall()
            conn.close()
            # Reverse to chronological order
            return [dict(r) for r in reversed(rows)]
        else:
            cursor.execute(
                """
                SELECT m.* FROM messages m
                JOIN conversations c ON m.conversation_id = c.id
                WHERE m.conversation_id = ? AND c.user_id = ?
                ORDER BY m.id ASC
                """,
                (conv_id, user_id)
            )
            rows = cursor.fetchall()
            conn.close()
            return [dict(r) for r in rows]

    @staticmethod
    def create(conv_id: int, user_id: int, role: str, content: str) -> dict:
        """Insert message for conversation owned by user_id"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO messages (conversation_id, user_id, role, content) VALUES (?, ?, ?, ?)",
            (conv_id, user_id, role, content)
        )
        msg_id = cursor.lastrowid
        conn.commit()

        # Update parent conversation updated_at
        cursor.execute("UPDATE conversations SET updated_at = datetime('now') WHERE id = ? AND user_id = ?", (conv_id, user_id))
        conn.commit()

        cursor.execute("SELECT * FROM messages WHERE id = ?", (msg_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row)

    @staticmethod
    def count_by_conversation(conv_id: int, user_id: int) -> int:
        """Count messages in conversation owned by user_id"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT COUNT(*) as count FROM messages m
            JOIN conversations c ON m.conversation_id = c.id
            WHERE m.conversation_id = ? AND c.user_id = ?
            """,
            (conv_id, user_id)
        )
        row = cursor.fetchone()
        conn.close()
        return row["count"] if row else 0

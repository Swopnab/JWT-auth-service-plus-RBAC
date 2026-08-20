"""
Memory Service for Zabum AI - Isolated per Authenticated User
"""

import re
from typing import Optional
from config import MAX_RETRIEVED_MEMORIES
from models.memory import MemoryModel

class MemoryService:
    @staticmethod
    def get_relevant_memories(user_id: int, query: str, limit: int = MAX_RETRIEVED_MEMORIES) -> list[dict]:
        """
        Find user memories most relevant to the current user query.
        Returns top keyword matches or general preferences.
        """
        all_memories = MemoryModel.get_all(user_id=user_id)
        if not all_memories:
            return []

        query_tokens = set(re.findall(r"\w+", query.lower()))
        stop_words = {"the", "a", "an", "is", "are", "was", "were", "what", "how", "why", "to", "in", "of", "and", "or", "for", "me", "my", "i", "do", "you", "tell", "show"}
        meaningful_tokens = query_tokens - stop_words

        scored = []
        for mem in all_memories:
            content = mem["content"].lower()
            mem_tokens = set(re.findall(r"\w+", content))

            matches = len(meaningful_tokens.intersection(mem_tokens)) if meaningful_tokens else 0
            category_boost = 1 if mem.get("category") in ["preference", "profile", "identity"] else 0

            score = matches * 2 + category_boost
            scored.append({
                "id": mem["id"],
                "content": mem["content"],
                "category": mem["category"],
                "score": score
            })

        scored.sort(key=lambda x: x["score"], reverse=True)
        top = [m for m in scored if m["score"] > 0]
        if not top:
            top = scored[:limit]
        return top[:limit]

    @staticmethod
    def extract_and_save_memory(user_id: int, user_message: str) -> list[dict]:
        """
        Detects if the user is asking the assistant to remember something,
        extracts the statement, and stores it in SQLite linked to user_id.
        """
        text = user_message.strip()
        saved = []

        explicit_patterns = [
            (r"(?:please\s+)?remember\s+that\s+(.*)", "preference"),
            (r"(?:please\s+)?remember[:\s]+(.*)", "preference"),
            (r"(?:keep\s+in\s+mind\s+that\s+)(.*)", "preference"),
            (r"(?:note\s+that\s+)(.*)", "fact"),
            (r"(?:don'?t\s+forget\s+that\s+)(.*)", "preference"),
            (r"^(?:my\s+name\s+is\s+)(.*)", "identity"),
            (r"^(?:i\s+prefer\s+)(.*)", "preference"),
            (r"^(?:i\s+like\s+)(.*)", "preference"),
        ]

        matched_content = None
        category = "general"

        for pattern, cat in explicit_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                matched_content = match.group(1).strip().rstrip(".!?,")
                category = cat
                break

        if matched_content and len(matched_content) > 3:
            if not matched_content.lower().startswith("user") and not matched_content.lower().startswith("i "):
                clean_content = f"User preference: {matched_content}"
            elif matched_content.lower().startswith("i "):
                clean_content = f"User {matched_content[2:]}"
            else:
                clean_content = matched_content

            if not MemoryModel.exists_similar(user_id, clean_content):
                mem = MemoryModel.create(user_id=user_id, content=clean_content, category=category)
                saved.append(mem)
                return saved

        return saved


_memory_service_instance = None

def get_memory_service() -> MemoryService:
    global _memory_service_instance
    if _memory_service_instance is None:
        _memory_service_instance = MemoryService()
    return _memory_service_instance

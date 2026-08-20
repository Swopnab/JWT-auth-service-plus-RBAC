"""
Zabum AI Assistant - Configuration Settings
Integrates with Cloudflare Worker RBAC Auth Service and Local Ollama Llama 3.2
"""

import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR / "storage"
DB_PATH = STORAGE_DIR / "zabum.db"

# Ensure storage directory exists
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

# Cloudflare Worker RBAC Auth Backend
CF_AUTH_WORKER_URL = os.getenv("CF_AUTH_WORKER_URL", "http://127.0.0.1:8787")

# Ollama / AI Provider Configuration
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
OLLAMA_EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")
AI_PROVIDER = os.getenv("AI_PROVIDER", "ollama")  # 'ollama', 'mock', etc.

# Context & Memory Parameters
MAX_RECENT_MESSAGES = 12
MAX_RETRIEVED_MEMORIES = 6

# Server Port
PORT = int(os.getenv("PORT", 5001))

# System Prompt
SYSTEM_PROMPT = """You are Zabum AI, a private, intelligent, and highly capable personal AI assistant.

Your core traits:
1. Helpful & Concise: Provide clear, direct, and well-structured answers without unnecessary fluff.
2. Technically Capable: Expert in programming, software architecture, reasoning, analysis, and problem-solving.
3. Conversational & Polite: Engage naturally with the user while maintaining professional quality.
4. Honest & Grounded: If you do not know something or if information is not present in the provided context, state it honestly rather than hallucinating.
5. Personal Context Aware: When user memories are provided, use them seamlessly to personalize and enrich your responses.

Formatting Rules:
- Use GitHub Flavored Markdown for formatting.
- Always use syntax-highlighted code blocks with the appropriate language identifier for code snippets.
- Use bullet points and bold text for readability when explaining multi-part concepts.
"""

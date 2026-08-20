"""
AI Provider Interface and Implementations for Zabum AI
Supports local Ollama (Llama 3.2), Mock Provider, and clean extension points for cloud models
"""

import abc
import requests
from config import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_EMBED_MODEL

class BaseAIProvider(abc.ABC):
    @abc.abstractmethod
    def is_available(self) -> tuple[bool, str]:
        """Check if provider backend is reachable and available"""
        pass

    @abc.abstractmethod
    def chat(self, messages: list[dict], options: dict = None) -> str:
        """Execute chat completion turn given list of message dicts"""
        pass

    @abc.abstractmethod
    def generate(self, prompt: str, system_prompt: str = None, options: dict = None) -> str:
        """Generate single completion from prompt"""
        pass


class OllamaProvider(BaseAIProvider):
    def __init__(self, model_name: str = OLLAMA_MODEL, base_url: str = OLLAMA_BASE_URL):
        self.model_name = model_name
        self.base_url = base_url.rstrip("/")
        self.generate_url = f"{self.base_url}/api/generate"
        self.chat_url = f"{self.base_url}/api/chat"
        self.tags_url = f"{self.base_url}/api/tags"

    def is_available(self) -> tuple[bool, str]:
        try:
            res = requests.get(self.tags_url, timeout=3)
            if res.status_code == 200:
                data = res.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                has_model = any(self.model_name in m for m in models)
                if has_model:
                    return True, f"Connected to Ollama ({self.model_name})"
                else:
                    return False, f"Ollama is running, but model '{self.model_name}' is not found. Run 'ollama pull {self.model_name}'."
            return False, f"Ollama responded with status code {res.status_code}."
        except requests.exceptions.ConnectionError:
            return False, "Ollama is not running. Start Ollama with 'ollama serve'."
        except Exception as e:
            return False, f"Ollama connection error: {str(e)}"

    def chat(self, messages: list[dict], options: dict = None) -> str:
        payload = {
            "model": self.model_name,
            "messages": messages,
            "stream": False,
            "options": options or {"temperature": 0.6}
        }
        try:
            res = requests.post(self.chat_url, json=payload, timeout=90)
            if res.status_code == 200:
                data = res.json()
                msg = data.get("message", {})
                return msg.get("content", "").strip()
            else:
                raise Exception(f"Ollama returned HTTP {res.status_code}: {res.text}")
        except requests.exceptions.ConnectionError:
            raise ConnectionError(
                "Zabum AI is offline. Start Ollama to use the assistant: 'ollama serve' and 'ollama pull llama3.2'."
            )
        except Exception as e:
            raise Exception(f"AI Chat Error: {str(e)}")

    def generate(self, prompt: str, system_prompt: str = None, options: dict = None) -> str:
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": options or {"temperature": 0.4}
        }
        if system_prompt:
            payload["system"] = system_prompt

        try:
            res = requests.post(self.generate_url, json=payload, timeout=60)
            if res.status_code == 200:
                data = res.json()
                return data.get("response", "").strip()
            else:
                raise Exception(f"Ollama returned HTTP {res.status_code}: {res.text}")
        except requests.exceptions.ConnectionError:
            raise ConnectionError(
                "Zabum AI is offline. Start Ollama to use the assistant: 'ollama serve' and 'ollama pull llama3.2'."
            )
        except Exception as e:
            raise Exception(f"AI Generation Error: {str(e)}")


class MockProvider(BaseAIProvider):
    """Fallback Mock Provider for development/testing when Ollama is offline"""
    def is_available(self) -> tuple[bool, str]:
        return True, "Mock Provider (Offline Demo Mode)"

    def chat(self, messages: list[dict], options: dict = None) -> str:
        last_msg = messages[-1]["content"] if messages else ""
        return (
            f"Hello! I am **Zabum AI** (Mock Demo Mode).\n\n"
            f"I received your message: *\"{last_msg}\"*\n\n"
            f"To enable real local intelligence with Llama 3.2:\n"
            f"1. Run `ollama serve`\n"
            f"2. Run `ollama pull llama3.2`"
        )

    def generate(self, prompt: str, system_prompt: str = None, options: dict = None) -> str:
        return f"Mock Title: {prompt[:30]}"


_provider_instance = None

def get_ai_provider() -> BaseAIProvider:
    global _provider_instance
    if _provider_instance is None:
        _provider_instance = OllamaProvider()
    return _provider_instance

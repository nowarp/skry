import os
from typing import Dict, Any, List, Optional

from llm.api.base import LLMProvider, LLMResponse

try:
    import requests  # ty: ignore[unresolved-import]
except ImportError:
    requests = None  # ty: ignore[invalid-assignment]


DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
DEEPSEEK_MODEL = "deepseek-chat"


class DeepSeekProvider(LLMProvider):
    """DeepSeek API provider implementation."""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize DeepSeek provider.

        Args:
            api_key: API key. If None, reads from DEEPSEEK_API_KEY env var.
        """
        self._api_key = api_key or os.environ.get("DEEPSEEK_API_KEY")

    @property
    def name(self) -> str:
        return "DeepSeek"

    def is_available(self) -> bool:
        """Check if DeepSeek is configured."""
        if requests is None:
            return False
        return bool(self._api_key)

    def call(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        """Call DeepSeek API."""
        if requests is None:
            return LLMResponse(
                content="",
                input_tokens=0,
                output_tokens=0,
                error="'requests' library not installed. Install with: pip install requests",
            )

        if not self._api_key:
            return LLMResponse(
                content="",
                input_tokens=0,
                output_tokens=0,
                error="DEEPSEEK_API_KEY environment variable not set",
            )

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._api_key}",
        }

        payload: Dict[str, Any] = {
            "model": DEEPSEEK_MODEL,
            "messages": messages,
            "temperature": temperature,
        }

        if max_tokens is not None:
            payload["max_tokens"] = max_tokens

        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        try:
            response = requests.post(
                DEEPSEEK_API_URL,
                headers=headers,
                json=payload,
                timeout=60,
            )
            response.raise_for_status()

            data = response.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()

            # Extract token usage
            usage = data.get("usage", {})
            input_tokens = usage.get("prompt_tokens", 0)
            output_tokens = usage.get("completion_tokens", 0)

            # Estimate if not provided
            if input_tokens == 0:
                total_prompt = " ".join(m.get("content", "") for m in messages)
                input_tokens = len(total_prompt) // 4
            if output_tokens == 0:
                output_tokens = len(content) // 4

            return LLMResponse(
                content=content,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )

        except requests.exceptions.RequestException as e:
            return LLMResponse(
                content="",
                input_tokens=0,
                output_tokens=0,
                error=f"API request failed: {e}",
            )
        except Exception as e:
            return LLMResponse(
                content="",
                input_tokens=0,
                output_tokens=0,
                error=f"Failed to process response: {e}",
            )


# Singleton instance for convenience
_default_provider: Optional[DeepSeekProvider] = None


def get_default_provider() -> DeepSeekProvider:
    """Get or create the default DeepSeek provider instance."""
    global _default_provider
    if _default_provider is None:
        _default_provider = DeepSeekProvider()
    return _default_provider

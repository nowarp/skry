from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class LLMResponse:
    """Standardized response from LLM provider."""

    content: str
    input_tokens: int
    output_tokens: int
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.error is None


class LLMProvider(ABC):
    """Abstract base class for LLM API providers."""

    @abstractmethod
    def call(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        """
        Call the LLM with a list of messages.

        Args:
            messages: List of message dicts with 'role' and 'content' keys.
            temperature: Sampling temperature (0.0-1.0).
            max_tokens: Maximum tokens in response (None for default).
            json_mode: If True, request JSON-formatted response.

        Returns:
            LLMResponse with content or error.
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the provider is configured and available."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name for logging/display."""
        pass

import shutil
import subprocess
from abc import abstractmethod
from typing import Any, Dict, List, Optional

from llm.api.base import LLMProvider, LLMResponse


class CLIProvider(LLMProvider):
    """Abstract base for CLI-based LLM providers."""

    def __init__(self, timeout: int = 120):
        self._timeout = timeout

    @property
    @abstractmethod
    def cli_command(self) -> str:
        """The CLI command name (e.g., 'claude')."""
        pass

    @abstractmethod
    def build_args(
        self,
        messages: List[Dict[str, str]],
        json_mode: bool = False,
        json_schema: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """Build CLI arguments from messages."""
        pass

    @abstractmethod
    def parse_output(self, stdout: str) -> LLMResponse:
        """Parse CLI stdout to LLMResponse."""
        pass

    def is_available(self) -> bool:
        return shutil.which(self.cli_command) is not None

    def call(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        if not self.is_available():
            return LLMResponse(
                content="",
                input_tokens=0,
                output_tokens=0,
                error=f"CLI '{self.cli_command}' not found",
            )

        args = self.build_args(messages, json_mode=json_mode)

        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )

            if result.returncode != 0:
                return LLMResponse(
                    content="",
                    input_tokens=0,
                    output_tokens=0,
                    error=f"CLI exit {result.returncode}: {result.stderr[:500]}",
                )

            return self.parse_output(result.stdout)

        except subprocess.TimeoutExpired:
            return LLMResponse(
                content="",
                input_tokens=0,
                output_tokens=0,
                error=f"CLI timed out after {self._timeout}s",
            )
        except Exception as e:
            return LLMResponse(
                content="",
                input_tokens=0,
                output_tokens=0,
                error=f"CLI failed: {e}",
            )

    def call_with_schema(
        self,
        messages: List[Dict[str, str]],
        json_schema: Dict[str, Any],
    ) -> LLMResponse:
        """Call with explicit JSON schema (for providers that support it)."""
        if not self.is_available():
            return LLMResponse(
                content="",
                input_tokens=0,
                output_tokens=0,
                error=f"CLI '{self.cli_command}' not found",
            )

        args = self.build_args(messages, json_mode=True, json_schema=json_schema)

        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )

            if result.returncode != 0:
                return LLMResponse(
                    content="",
                    input_tokens=0,
                    output_tokens=0,
                    error=f"CLI exit {result.returncode}: {result.stderr[:500]}",
                )

            return self.parse_output(result.stdout)

        except subprocess.TimeoutExpired:
            return LLMResponse(
                content="",
                input_tokens=0,
                output_tokens=0,
                error=f"CLI timed out after {self._timeout}s",
            )
        except Exception as e:
            return LLMResponse(
                content="",
                input_tokens=0,
                output_tokens=0,
                error=f"CLI failed: {e}",
            )

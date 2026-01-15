import json
from typing import Any, Dict, List, Optional

from llm.api.cli_base import CLIProvider
from llm.api.base import LLMResponse


class ClaudeCLIProvider(CLIProvider):
    """Claude Code CLI provider."""

    @property
    def cli_command(self) -> str:
        return "claude"

    @property
    def name(self) -> str:
        return "Claude CLI"

    def build_args(
        self,
        messages: List[Dict[str, str]],
        json_mode: bool = False,
        json_schema: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        prompt_parts = []
        system_prompt = None

        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "system":
                system_prompt = content
            else:
                prompt_parts.append(content)

        prompt = "\n\n".join(prompt_parts)

        args = ["claude", "-p", "--output-format", "json"]

        # Disable all tools to make pure prompt-based decisions
        args.extend(["--tools", ""])

        if system_prompt:
            args.extend(["--system-prompt", system_prompt])

        if json_schema:
            args.extend(["--json-schema", json.dumps(json_schema)])

        args.append(prompt)
        return args

    def parse_output(self, stdout: str) -> LLMResponse:
        try:
            data = json.loads(stdout)

            # Check for structured output (when --json-schema used)
            if "structured_output" in data:
                content = json.dumps(data["structured_output"])
            else:
                content = data.get("result", "")

            usage = data.get("usage", {})
            input_tokens = usage.get("input_tokens", 0)
            output_tokens = usage.get("output_tokens", 0)

            if data.get("is_error", False):
                return LLMResponse(
                    content="",
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    error=content,
                )

            return LLMResponse(
                content=content,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )

        except json.JSONDecodeError as e:
            return LLMResponse(
                content="",
                input_tokens=0,
                output_tokens=0,
                error=f"Failed to parse CLI output: {e}",
            )

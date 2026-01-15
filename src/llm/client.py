import os
import sys
import json
import re
from core.utils import error, warn, info, debug
from typing import Optional, Dict, Any

from llm.api.deepseek import DeepSeekProvider, get_default_provider
from llm.api.claude_cli import ClaudeCLIProvider
from llm.api.base import LLMProvider
from llm.prompt_cache import PromptCache
from prompts import render as render_prompt

# Debug cache directory for LLM responses
LLM_DEBUG_CACHE_DIR = ".skry_cache/llm_debug"


def is_llm_debug_enabled() -> bool:
    """Check if LLM debug mode is enabled via SKRY_LLM_DEBUG=1."""
    return os.environ.get("SKRY_LLM_DEBUG", "0").lower() == "1"


def is_llm_nocache_enabled() -> bool:
    """Check if LLM cache bypass is enabled via SKRY_LLM_NOCACHE=1."""
    return os.environ.get("SKRY_LLM_NOCACHE", "0").lower() == "1"


def is_print_full_prompt_enabled() -> bool:
    """Check if full prompt printing is enabled via SKRY_PRINT_FULL_PROMPT=1."""
    return os.environ.get("SKRY_PRINT_FULL_PROMPT", "0").lower() == "1"


def _prompt_header(prompt: str, max_len: int = 60) -> str:
    """Extract first meaningful line from prompt as header."""
    for line in prompt.split("\n"):
        line = line.strip()
        # Skip empty, brackets, markdown headers, code blocks
        if not line or line.startswith(("[", "#", "```", "---")):
            continue
        if len(line) > max_len:
            return line[:max_len] + "..."
        return line
    return prompt[:max_len] + "..." if len(prompt) > max_len else prompt


def _save_debug_response(prompt: str, response: Dict[str, Any]) -> None:
    """Save LLM prompt and response to debug cache."""
    import hashlib
    from datetime import datetime

    os.makedirs(LLM_DEBUG_CACHE_DIR, exist_ok=True)

    # Create hash from prompt for filename
    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:16]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{timestamp}_{prompt_hash}.json"
    filepath = os.path.join(LLM_DEBUG_CACHE_DIR, filename)

    debug_data = {
        "timestamp": datetime.now().isoformat(),
        "prompt": prompt,
        "response": response,
    }

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(debug_data, f, indent=2)
    except Exception as e:
        warn(f"Failed to save LLM debug response: {e}")


# Global prompt cache instance
_prompt_cache = PromptCache()


def get_llm_mode() -> str:
    """Get LLM mode from environment variable."""
    return os.environ.get("SKRY_LLM_MODE", "api").lower()


def _get_cli_provider(mode: str) -> Optional[LLMProvider]:
    """Get CLI provider based on mode."""
    if mode == "claude-cli":
        provider = ClaudeCLIProvider()
        if not provider.is_available():
            error("Claude CLI not found. Install from https://claude.ai/claude-code")
            return None
        return provider
    else:
        error(f"Unknown CLI mode: {mode}. Use 'claude-cli'.")
        return None


def _copy_to_clipboard(text: str) -> None:
    """Copy text to clipboard using xclip if SKRY_COPYPASTE=1."""
    if os.environ.get("SKRY_COPYPASTE", "0").lower() == "1":
        import subprocess

        try:
            subprocess.run(
                ["xclip", "-selection", "clipboard"],
                input=text.encode("utf-8"),
                check=True,
            )
            subprocess.run(
                ["notify-send", "skry", "Prompt copied to clipboard"],
                check=False,
            )
        except FileNotFoundError:
            warn("xclip not found, cannot copy to clipboard")
        except subprocess.CalledProcessError as e:
            warn(f"Failed to copy to clipboard: {e}")


def _read_multiline_input() -> tuple[str, bool]:
    """
    Read multiline input from stdin.
    Input ends when user presses Enter twice (empty line after content).
    Double-enter without any content skips the query.

    Returns:
        Tuple of (response_text, skipped) where skipped=True if user pressed Enter twice without input.
    """
    lines = []
    empty_count = 0

    while True:
        try:
            line = input()
        except EOFError:
            break

        if line == "":
            empty_count += 1
            if empty_count >= 2:
                if not lines:
                    # Double-enter without content = skip
                    info("Skipped.")
                    return "", True
                else:
                    # Two consecutive empty lines after content -> done
                    break
            elif lines:
                # Single empty line within content -> keep it
                lines.append("")
        else:
            empty_count = 0
            lines.append(line)

    info("Accepted.")
    return "\n".join(lines).strip(), False


def _check_cache(prompt: str) -> Optional[Dict[str, Any]]:
    """Check prompt cache and return cached result if found."""
    if is_llm_nocache_enabled():
        debug("[llm] Cache bypass enabled (SKRY_LLM_NOCACHE=1)")
        return None
    cached = _prompt_cache.get(prompt)
    if cached is not None:
        debug(f"[llm] Prompt cache HIT (hash={_prompt_cache._hash(prompt)})")
        return cached
    debug(f"[llm] Prompt cache MISS (hash={_prompt_cache._hash(prompt)})")
    return None


def _store_cache(prompt: str, result: Dict[str, Any], skip_errors: bool = True) -> None:
    """Store result in prompt cache."""
    if skip_errors and "error" in result:
        return
    if result.get("skipped"):
        return
    _prompt_cache.put(prompt, "cached", result)


def call_llm_batch(
    prompt: str,
    api_key: Optional[str] = None,
    context: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Call LLM with a batched prompt expecting JSON response with multiple answers.

    If SKRY_LLM_DEBUG=1, automatically requests "reason" and "needs_more_info"
    fields in the response and saves to debug cache.

    Args:
        prompt: The prompt to send
        api_key: Optional API key override
        context: Optional label for this prompt (shown in headers)

    Returns:
        Dictionary with 'results' key containing {question_id: boolean} mappings.
        In debug mode, also includes:
        - "reason": LLM's explanation for the decisions
        - "needs_more_info": what context is missing if LLM is guessing
    """
    debug_mode = is_llm_debug_enabled()

    # In debug mode, add request for reasoning
    if debug_mode:
        prompt = prompt + render_prompt("system/debug_extension_batch.j2")

    mode = get_llm_mode()
    if mode == "manual":
        return _manual_mode_batch(prompt, context)
    elif mode.endswith("-cli"):
        return _cli_mode_batch(prompt, mode, context)
    else:
        return _auto_mode_batch(prompt, api_key, context)


def _manual_mode_batch(prompt: str, context: Optional[str] = None) -> Dict[str, Any]:
    """Print prompt and wait for user to provide JSON response."""
    cached = _check_cache(prompt)
    if cached is not None:
        return cached

    header = f"LLM BATCH PROMPT (Manual Mode) - {context}" if context else "LLM BATCH PROMPT (Manual Mode)"
    print("\n" + "=" * 80, file=sys.stderr)
    print(header, file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    print(prompt, file=sys.stderr)
    _copy_to_clipboard(prompt)
    print("=" * 80, file=sys.stderr)
    print("\nPaste the JSON response (double-Enter to skip):", file=sys.stderr)

    response_text, skipped = _read_multiline_input()
    if skipped:
        return {"results": {}, "skipped": True}

    try:
        parsed = json.loads(response_text)
        results = {}
        for k, v in parsed.items():
            if isinstance(v, bool):
                results[k] = v
            elif isinstance(v, str):
                results[k] = v.lower() in ("true", "t", "yes", "1")
            else:
                results[k] = bool(v)
        result = {"results": results}
        _store_cache(prompt, result)
        return result
    except json.JSONDecodeError as e:
        error(f"Failed to parse JSON response: {e}")
        return {"results": {}}


def _auto_mode_batch(prompt: str, api_key: Optional[str] = None, context: Optional[str] = None) -> Dict[str, Any]:
    """Call LLM API with batched prompt expecting JSON response."""
    cached = _check_cache(prompt)
    if cached is not None:
        return cached

    provider = DeepSeekProvider(api_key) if api_key else get_default_provider()
    if not provider.is_available():
        error(f"{provider.name} not available. Check API key and dependencies.")
        return {"results": {}}

    messages = [
        {"role": "system", "content": render_prompt("system/batch.j2")},
        {"role": "user", "content": prompt},
    ]

    label = f"[llm:{context}]" if context else "[llm]"
    if is_llm_debug_enabled():
        info(f"{label} Asking ({_prompt_cache._hash(prompt)}):\n{prompt}")
    elif is_print_full_prompt_enabled():
        info(f"{label} Asking (hash={_prompt_cache._hash(prompt)}):\n{prompt}")
    else:
        info(f"{label} Asking: {_prompt_header(prompt)}")
    response = provider.call(messages, temperature=0.1, json_mode=True)
    if not response.success:
        error(f"LLM API request failed: {response.error}")
        return {"results": {}}

    result = _parse_json_response(response.content)
    if is_llm_debug_enabled():
        info(f"{label} Response:\n{response.content}")
        _save_debug_response(prompt, result)
    else:
        info(f"{label} Got {len(result.get('results', {}))} answers")
    _store_cache(prompt, result)
    return result


def _parse_json_response(content: str) -> Dict[str, Any]:
    """Parse JSON response from LLM, handling various edge cases.

    Preserves 'reason' and 'needs_more_info' fields if present (debug mode).
    """
    # Remove markdown code blocks if present
    content = content.strip()
    if content.startswith("```"):
        # Remove opening ```json or ``` and closing ```
        lines = content.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        content = "\n".join(lines)

    # Try to parse as JSON
    try:
        parsed = json.loads(content)

        # Handle array responses (e.g., sensitivity analysis returns arrays)
        if isinstance(parsed, list):
            return {"results": parsed}

        # Check if response has nested "results" structure (debug mode format)
        if "results" in parsed and isinstance(parsed["results"], dict):
            results = {}
            for k, v in parsed["results"].items():
                if isinstance(v, bool):
                    results[k] = v
                elif isinstance(v, str):
                    results[k] = v.lower() in ("true", "t", "yes", "1")
                else:
                    results[k] = bool(v)
            response = {"results": results}
            # Preserve debug fields
            if "reason" in parsed:
                response["reason"] = str(parsed["reason"])
            if "needs_more_info" in parsed:
                response["needs_more_info"] = str(parsed["needs_more_info"])
            return response

        results = {}
        for k, v in parsed.items():
            if k in ("reason", "needs_more_info"):
                continue  # Skip debug fields in flat format
            if isinstance(v, bool):
                results[k] = v
            elif isinstance(v, str):
                results[k] = v.lower() in ("true", "t", "yes", "1")
            else:
                results[k] = bool(v)

        response = {"results": results}
        # Preserve debug fields from flat format too
        if "reason" in parsed:
            response["reason"] = str(parsed["reason"])
        if "needs_more_info" in parsed:
            response["needs_more_info"] = str(parsed["needs_more_info"])
        return response

    except json.JSONDecodeError:
        # Try to extract JSON from the response
        json_match = re.search(r"\{[^{}]*\}", content, re.DOTALL)
        if json_match:
            try:
                parsed = json.loads(json_match.group())
                results = {}
                for k, v in parsed.items():
                    if k in ("reason", "needs_more_info"):
                        continue
                    if isinstance(v, bool):
                        results[k] = v
                    elif isinstance(v, str):
                        results[k] = v.lower() in ("true", "t", "yes", "1")
                    else:
                        results[k] = bool(v)
                return {"results": results}
            except json.JSONDecodeError:
                pass

        # Failed to parse - log and return empty
        warn(f"Failed to parse LLM JSON response: {content[:200]}")
        return {"results": {}}


def call_llm_json(
    prompt: str,
    schema: Dict[str, type],
    api_key: Optional[str] = None,
    context: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Call LLM with prompt and enforce JSON response with specified schema.

    If SKRY_LLM_DEBUG=1, automatically adds "reason" field to schema and
    saves prompt/response to .skry_cache/llm_debug/.

    Args:
        prompt: The prompt to send (question context)
        schema: Expected response schema, e.g. {"is_user_asset": bool}
        api_key: Optional API key override

    Returns:
        Dictionary with parsed response fields, or {"error": ...} if failed.
        In debug mode, includes:
        - "reason": LLM's explanation for the decision
        - "needs_more_info": what context is missing if LLM is guessing (empty if confident)
    """
    debug_mode = is_llm_debug_enabled()

    # In debug mode, add reason and needs_more_info fields to schema
    effective_schema = schema.copy()
    if debug_mode:
        if "reason" not in effective_schema:
            effective_schema["reason"] = str
        if "needs_more_info" not in effective_schema:
            effective_schema["needs_more_info"] = str

    # Build schema description for prompt
    schema_desc = ", ".join(f'"{k}": {v.__name__}' for k, v in effective_schema.items())
    schema_example = _build_schema_example(effective_schema)

    # Add Sui Move context prefix
    prompt = f"[Sui Move smart contract analysis]\n\n{prompt}"

    # In debug mode, ask for reasoning and uncertainty
    if debug_mode:
        debug_ext = render_prompt("system/debug_extension_json.j2")
        full_prompt = f"""{prompt}
{debug_ext}

Answer in JSON format ONLY: {{{schema_desc}}}
Example: {schema_example}"""
    else:
        full_prompt = f"""{prompt}

Answer in JSON format ONLY: {{{schema_desc}}}
Example: {schema_example}"""

    mode = get_llm_mode()
    if mode == "manual":
        response = _manual_mode_json(full_prompt, effective_schema, context)
    elif mode.endswith("-cli"):
        response = _cli_mode_json(full_prompt, effective_schema, mode)
    else:
        response = _auto_mode_json(full_prompt, effective_schema, api_key)

    # Save to debug cache if enabled
    if debug_mode and "error" not in response:
        _save_debug_response(prompt, response)

    return response


def _build_schema_example(schema: Dict[str, type]) -> str:
    """Build example JSON for schema."""
    example = {}
    for k, v in schema.items():
        if v is bool:
            example[k] = True
        elif v is str:
            example[k] = "..."
        elif v is int:
            example[k] = 0
        elif v is float:
            example[k] = 0.0
        else:
            example[k] = None
    return json.dumps(example)


def _manual_mode_json(prompt: str, schema: Dict[str, type], context: Optional[str] = None) -> Dict[str, Any]:
    """Print prompt and wait for JSON response."""
    cached = _check_cache(prompt)
    if cached is not None:
        return cached

    header = f"LLM PROMPT (Manual Mode - JSON) - {context}" if context else "LLM PROMPT (Manual Mode - JSON)"
    print("\n" + "=" * 80, file=sys.stderr)
    print(header, file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    print(prompt, file=sys.stderr)
    _copy_to_clipboard(prompt)
    print("=" * 80, file=sys.stderr)
    print("\nPaste JSON response (double-Enter to skip):", file=sys.stderr)

    response_text, skipped = _read_multiline_input()
    if skipped:
        return {"error": "Skipped by user", "skipped": True}

    result = _parse_schema_response(response_text, schema)
    _store_cache(prompt, result)
    return result


def _auto_mode_json(
    prompt: str,
    schema: Dict[str, type],
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Call LLM API with JSON schema enforcement."""
    cached = _check_cache(prompt)
    if cached is not None:
        return cached

    provider = DeepSeekProvider(api_key) if api_key else get_default_provider()
    if not provider.is_available():
        return {"error": f"{provider.name} not available. Check API key and dependencies."}

    messages = [
        {"role": "system", "content": render_prompt("system/json.j2")},
        {"role": "user", "content": prompt},
    ]

    if is_llm_debug_enabled():
        info(f"[llm] Asking ({_prompt_cache._hash(prompt)}):\n{prompt}")
    elif is_print_full_prompt_enabled():
        info(f"[llm] Asking (hash={_prompt_cache._hash(prompt)}):\n{prompt}")
    else:
        info(f"[llm] Asking: {_prompt_header(prompt)}")
    response = provider.call(messages, temperature=0.1, json_mode=True)
    if not response.success:
        return {"error": f"API request failed: {response.error}"}

    result = _parse_schema_response(response.content, schema)
    if "error" not in result:
        if is_llm_debug_enabled():
            info(f"[llm] Response:\n{response.content}")
        else:
            info("[llm] OK")
    _store_cache(prompt, result)
    return result


def _extract_json_from_markdown(content: str) -> str | None:
    """Extract JSON from ```json ... ``` markdown block."""
    # Match ```json ... ``` or ``` ... ```
    match = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", content)
    if match:
        return match.group(1)
    return None


def _parse_schema_response(content: str, schema: Dict[str, type]) -> Dict[str, Any]:
    """Parse JSON response and validate against schema."""
    content = content.strip()

    # Try parsing directly first
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        # Try extracting from markdown code block
        json_str = _extract_json_from_markdown(content)
        if json_str:
            try:
                parsed = json.loads(json_str)
            except json.JSONDecodeError:
                return {"error": f"Failed to parse JSON from markdown: {content[:200]}"}
        else:
            # Last resort: try to find any JSON object (simple, no nesting)
            json_match = re.search(r"\{[^{}]*\}", content, re.DOTALL)
            if json_match:
                try:
                    parsed = json.loads(json_match.group())
                except json.JSONDecodeError:
                    return {"error": f"Failed to parse JSON: {content[:200]}"}
            else:
                return {"error": f"No JSON found in response: {content[:200]}"}

    # Validate and coerce types
    result = {}
    for key, expected_type in schema.items():
        if key not in parsed:
            return {"error": f"Missing key '{key}' in response"}

        value = parsed[key]

        if expected_type is bool:
            if isinstance(value, bool):
                result[key] = value
            elif isinstance(value, str):
                result[key] = value.lower() in ("true", "t", "yes", "1", "user")
            else:
                result[key] = bool(value)
        elif expected_type is str:
            result[key] = str(value)
        elif expected_type is int:
            result[key] = int(value)
        elif expected_type is float:
            result[key] = float(value)
        else:
            result[key] = value

    return result


def _build_json_schema(schema: Dict[str, type]) -> Dict[str, Any]:
    """Convert simple schema to JSON Schema format for Claude CLI."""
    properties = {}
    for key, typ in schema.items():
        if typ is bool:
            properties[key] = {"type": "boolean"}
        elif typ is str:
            properties[key] = {"type": "string"}
        elif typ is int:
            properties[key] = {"type": "integer"}
        elif typ is float:
            properties[key] = {"type": "number"}
        elif typ is list:
            properties[key] = {"type": "array"}

    return {
        "type": "object",
        "properties": properties,
        "required": list(schema.keys()),
    }


def _cli_mode_json(prompt: str, schema: Dict[str, type], mode: str) -> Dict[str, Any]:
    """Call CLI tool with JSON schema."""
    cached = _check_cache(prompt)
    if cached is not None:
        return cached

    provider = _get_cli_provider(mode)
    if provider is None:
        return {"error": "No CLI provider available"}

    messages = [
        {"role": "system", "content": render_prompt("system/cli.j2")},
        {"role": "user", "content": prompt},
    ]

    if is_llm_debug_enabled():
        info(f"[llm] Asking ({_prompt_cache._hash(prompt)}):\n{prompt}")
    elif is_print_full_prompt_enabled():
        info(f"[llm] Asking (hash={_prompt_cache._hash(prompt)}):\n{prompt}")
    else:
        info(f"[llm] Asking: {_prompt_header(prompt)}")

    # Claude CLI supports --json-schema
    if isinstance(provider, ClaudeCLIProvider):
        json_schema = _build_json_schema(schema)
        response = provider.call_with_schema(messages, json_schema)
    else:
        response = provider.call(messages, json_mode=True)

    if not response.success:
        return {"error": f"CLI failed: {response.error}"}

    result = _parse_schema_response(response.content, schema)
    if "error" not in result:
        if is_llm_debug_enabled():
            info(f"[llm] Response:\n{response.content}")
        else:
            info("[llm] OK")
    _store_cache(prompt, result)
    return result


def _cli_mode_batch(prompt: str, mode: str, context: Optional[str] = None) -> Dict[str, Any]:
    """Call CLI tool with batched prompt expecting JSON response."""
    cached = _check_cache(prompt)
    if cached is not None:
        return cached

    provider = _get_cli_provider(mode)
    if provider is None:
        return {"results": {}}

    messages = [
        {"role": "system", "content": render_prompt("system/batch.j2")},
        {"role": "user", "content": prompt},
    ]

    label = f"[llm:{context}]" if context else "[llm]"
    if is_llm_debug_enabled():
        info(f"{label} Asking ({_prompt_cache._hash(prompt)}):\n{prompt}")
    elif is_print_full_prompt_enabled():
        info(f"{label} Asking (hash={_prompt_cache._hash(prompt)}):\n{prompt}")
    else:
        info(f"{label} Asking: {_prompt_header(prompt)}")
    response = provider.call(messages, json_mode=True)
    if not response.success:
        error(f"CLI request failed: {response.error}")
        return {"results": {}}

    result = _parse_json_response(response.content)
    if is_llm_debug_enabled():
        info(f"{label} Response:\n{response.content}")
        _save_debug_response(prompt, result)
    else:
        info(f"{label} Got {len(result.get('results', {}))} answers")
    _store_cache(prompt, result)
    return result

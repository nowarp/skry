"""Tests for LLM debug mode (SKRY_LLM_DEBUG)."""

import os
import tempfile
from unittest.mock import patch

from llm.client import (
    call_llm_json,
    is_llm_debug_enabled,
    _save_debug_response,
)


class TestIsLlmDebugEnabled:
    """Tests for is_llm_debug_enabled function."""

    def test_disabled_by_default(self):
        """Debug mode should be disabled by default."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove SKRY_LLM_DEBUG if present
            os.environ.pop("SKRY_LLM_DEBUG", None)
            assert is_llm_debug_enabled() is False

    def test_enabled_with_env_var(self):
        """Debug mode should be enabled when SKRY_LLM_DEBUG=1."""
        with patch.dict(os.environ, {"SKRY_LLM_DEBUG": "1"}):
            assert is_llm_debug_enabled() is True

    def test_disabled_with_zero(self):
        """Debug mode should be disabled when SKRY_LLM_DEBUG=0."""
        with patch.dict(os.environ, {"SKRY_LLM_DEBUG": "0"}):
            assert is_llm_debug_enabled() is False


class TestCallLlmJsonDebugMode:
    """Tests for call_llm_json with debug mode."""

    def test_no_reason_field_without_debug(self):
        """Without debug mode, reason field should not be added to schema."""
        with patch.dict(os.environ, {"SKRY_LLM_DEBUG": "0", "SKRY_LLM_MODE": "manual"}):
            with patch("llm.client._manual_mode_json") as mock_manual:
                mock_manual.return_value = {"is_asset": True}

                call_llm_json("test prompt", {"is_asset": bool})

                # Check the schema passed to _manual_mode_json
                call_args = mock_manual.call_args
                schema_arg = call_args[0][1]  # Second positional arg is schema
                assert "reason" not in schema_arg

    def test_reason_field_added_with_debug(self):
        """With debug mode, reason field should be added to schema."""
        with patch.dict(os.environ, {"SKRY_LLM_DEBUG": "1", "SKRY_LLM_MODE": "manual"}):
            with patch("llm.client._manual_mode_json") as mock_manual:
                mock_manual.return_value = {"is_asset": True, "reason": "test reason"}

                call_llm_json("test prompt", {"is_asset": bool})

                # Check the schema passed to _manual_mode_json
                call_args = mock_manual.call_args
                schema_arg = call_args[0][1]
                assert "reason" in schema_arg
                assert schema_arg["reason"] is str

    def test_reason_not_duplicated_if_already_in_schema(self):
        """If schema already has reason, it should not be duplicated."""
        with patch.dict(os.environ, {"SKRY_LLM_DEBUG": "1", "SKRY_LLM_MODE": "manual"}):
            with patch("llm.client._manual_mode_json") as mock_manual:
                mock_manual.return_value = {"is_asset": True, "reason": "test"}

                # Pass schema that already has reason
                call_llm_json("test prompt", {"is_asset": bool, "reason": str})

                call_args = mock_manual.call_args
                schema_arg = call_args[0][1]
                # Should have reason exactly once
                assert list(schema_arg.keys()).count("reason") == 1

    def test_prompt_includes_reasoning_instruction_in_debug(self):
        """In debug mode, prompt should ask for reasoning."""
        with patch.dict(os.environ, {"SKRY_LLM_DEBUG": "1", "SKRY_LLM_MODE": "manual"}):
            with patch("llm.client._manual_mode_json") as mock_manual:
                mock_manual.return_value = {"is_asset": True, "reason": "test"}

                call_llm_json("test prompt", {"is_asset": bool})

                call_args = mock_manual.call_args
                prompt_arg = call_args[0][0]  # First positional arg is prompt
                assert "reasoning" in prompt_arg.lower()

    def test_prompt_no_reasoning_instruction_without_debug(self):
        """Without debug mode, prompt should not ask for reasoning."""
        with patch.dict(os.environ, {"SKRY_LLM_DEBUG": "0", "SKRY_LLM_MODE": "manual"}):
            with patch("llm.client._manual_mode_json") as mock_manual:
                mock_manual.return_value = {"is_asset": True}

                call_llm_json("test prompt", {"is_asset": bool})

                call_args = mock_manual.call_args
                prompt_arg = call_args[0][0]
                # Should not contain "Explain your reasoning"
                assert "Explain your reasoning" not in prompt_arg


class TestDebugCacheSaving:
    """Tests for debug response caching."""

    def test_save_debug_response_creates_file(self):
        """_save_debug_response should create a JSON file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("llm.client.LLM_DEBUG_CACHE_DIR", tmpdir):
                _save_debug_response("test prompt", {"result": True, "reason": "test"})

                files = os.listdir(tmpdir)
                assert len(files) == 1
                assert files[0].endswith(".json")

    def test_save_debug_response_contains_data(self):
        """Saved debug file should contain prompt and response."""
        import json

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("llm.client.LLM_DEBUG_CACHE_DIR", tmpdir):
                _save_debug_response("my test prompt", {"result": True, "reason": "my reason"})

                files = os.listdir(tmpdir)
                filepath = os.path.join(tmpdir, files[0])

                with open(filepath) as f:
                    data = json.load(f)

                assert data["prompt"] == "my test prompt"
                assert data["response"]["result"] is True
                assert data["response"]["reason"] == "my reason"
                assert "timestamp" in data

    def test_debug_cache_saved_only_in_debug_mode(self):
        """Debug cache should only be saved when SKRY_LLM_DEBUG=1."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("llm.client.LLM_DEBUG_CACHE_DIR", tmpdir):
                with patch.dict(os.environ, {"SKRY_LLM_DEBUG": "0", "SKRY_LLM_MODE": "manual"}):
                    with patch("llm.client._manual_mode_json") as mock_manual:
                        mock_manual.return_value = {"is_asset": True}

                        call_llm_json("test prompt", {"is_asset": bool})

                        # No debug files should be created
                        files = os.listdir(tmpdir) if os.path.exists(tmpdir) else []
                        assert len(files) == 0

    def test_debug_cache_saved_in_debug_mode(self):
        """Debug cache should be saved when SKRY_LLM_DEBUG=1."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("llm.client.LLM_DEBUG_CACHE_DIR", tmpdir):
                with patch.dict(os.environ, {"SKRY_LLM_DEBUG": "1", "SKRY_LLM_MODE": "manual"}):
                    with patch("llm.client._manual_mode_json") as mock_manual:
                        mock_manual.return_value = {"is_asset": True, "reason": "test"}

                        call_llm_json("test prompt", {"is_asset": bool})

                        files = os.listdir(tmpdir)
                        assert len(files) == 1

    def test_debug_cache_not_saved_on_error(self):
        """Debug cache should not be saved when LLM returns error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("llm.client.LLM_DEBUG_CACHE_DIR", tmpdir):
                with patch.dict(os.environ, {"SKRY_LLM_DEBUG": "1", "SKRY_LLM_MODE": "manual"}):
                    with patch("llm.client._manual_mode_json") as mock_manual:
                        mock_manual.return_value = {"error": "parse failed"}

                        call_llm_json("test prompt", {"is_asset": bool})

                        # No debug files on error
                        files = os.listdir(tmpdir) if os.path.exists(tmpdir) else []
                        assert len(files) == 0

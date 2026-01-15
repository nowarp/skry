"""Tests for LLM classification error handling."""

import os
import tempfile
from unittest.mock import patch


from semantic.llm_facts import generate_access_control_fact
from core.facts import Fact


class TestLLMClassifyErrorHandling:
    """Tests for error handling when LLM returns garbage."""

    def test_llm_error_returns_false(self):
        """When LLM returns garbage, function returns False and doesn't add fact."""
        facts = [
            Fact("Fun", ("test::foo",)),
            Fact("IsEntry", ("test::foo",)),
        ]
        source = "module test { public entry fun foo() {} }"
        initial_fact_count = len(facts)

        # Mock call_llm_json to return an error
        with patch("semantic.llm_facts.call_llm_json") as mock_llm:
            mock_llm.return_value = {"error": "Failed to parse JSON: garbage response"}

            is_vulnerable = generate_access_control_fact(
                func_name="test::foo",
                file_path="test.move",
                facts=facts,
                source_code=source,
                root=None,
                ctx=None,
            )

            assert is_vulnerable is False
            # On error, no fact should be added
            assert len(facts) == initial_fact_count

    def test_llm_error_not_cached(self):
        """When LLM returns error, result should NOT be cached."""
        # Use temp directory for cache
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("llm.cache.access_control_cache.cache_dir", tmpdir):
                facts = [
                    Fact("Fun", ("test::bar",)),
                    Fact("IsEntry", ("test::bar",)),
                ]
                source = "module test { public entry fun bar() {} }"

                # Mock call_llm_json to return an error
                with patch("semantic.llm_facts.call_llm_json") as mock_llm:
                    mock_llm.return_value = {"error": "API timeout"}

                    generate_access_control_fact(
                        func_name="test::bar",
                        file_path="test.move",
                        facts=facts,
                        source_code=source,
                        root=None,
                        ctx=None,
                    )

                # Check cache is empty
                cache_files = os.listdir(tmpdir)
                assert len(cache_files) == 0, f"Expected no cache files, found: {cache_files}"

    def test_successful_response_is_cached(self):
        """When LLM returns valid response, result should be cached."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("llm.cache.access_control_cache.cache_dir", tmpdir):
                facts = [
                    Fact("Fun", ("test::baz",)),
                    Fact("IsEntry", ("test::baz",)),
                ]
                source = "module test { public entry fun baz() {} }"

                # Mock call_llm_json to return valid response
                with patch("semantic.llm_facts.call_llm_json") as mock_llm:
                    mock_llm.return_value = {"is_vulnerable": True, "has_access_control": False, "reason": "No auth check"}

                    is_vulnerable = generate_access_control_fact(
                        func_name="test::baz",
                        file_path="test.move",
                        facts=facts,
                        source_code=source,
                        root=None,
                        ctx=None,
                    )

                    assert is_vulnerable is True
                    # Should add LLMVulnerableAccessControl fact
                    assert any(f.name == "LLMVulnerableAccessControl" and f.args[0] == "test::baz" for f in facts)

                # Check cache has file
                cache_files = os.listdir(tmpdir)
                assert len(cache_files) == 1, f"Expected 1 cache file, found: {cache_files}"

    def test_llm_error_prints_error_message(self, capsys):
        """When LLM fails, error message should be printed to stderr."""
        facts = [
            Fact("Fun", ("test::qux",)),
            Fact("IsEntry", ("test::qux",)),
        ]
        source = "module test { public entry fun qux() {} }"

        with patch("semantic.llm_facts.call_llm_json") as mock_llm:
            mock_llm.return_value = {"error": "Connection refused"}

            generate_access_control_fact(
                func_name="test::qux",
                file_path="test.move",
                facts=facts,
                source_code=source,
                root=None,
                ctx=None,
            )

        captured = capsys.readouterr()
        assert "test::qux" in captured.err
        assert "Connection refused" in captured.err


class TestErrorFunctionFormatting:
    """Tests for error() function formatting."""

    def test_error_contains_bold_red_prefix(self, capsys):
        """error() should print [ERROR] in bold red."""
        from core.utils import error

        error("test message")

        captured = capsys.readouterr()
        # Check for ANSI escape codes: \033[1;31m = bold red, \033[0m = reset
        assert "\033[1;31m[ERROR]\033[0m" in captured.err
        assert "test message" in captured.err

"""Tests for sensitive setter detection (unauth-sensitive-setter rule).

Tests:
- Pre-filter: operates-on-shared-object
- Pre-filter: no role check
- Pre-filter: no sensitive sink (those handled by other rules)
- Pre-filter: not user asset container
- LLM classification: protocol config vs user state
"""

from unittest.mock import patch

from core.facts import Fact
from semantic.llm_facts import generate_sensitive_setter_fact
from llm.prompts import get_mutable_shared_param_types


class TestMutableSharedParamTypes:
    """Test extraction of mutable shared param types."""

    def test_extracts_mut_shared_param(self):
        """Function with &mut to shared object type is detected."""
        facts = [
            Fact("FormalArg", ("test::set_fee", 0, "pool", "&mut Pool")),
            Fact("FormalArg", ("test::set_fee", 1, "new_fee", "u64")),
            Fact("IsSharedObject", ("Pool",)),
        ]

        result = get_mutable_shared_param_types("test::set_fee", facts)

        assert "Pool" in result

    def test_ignores_non_mut_shared(self):
        """Immutable reference to shared object is not flagged."""
        facts = [
            Fact("FormalArg", ("test::get_fee", 0, "pool", "&Pool")),
            Fact("IsSharedObject", ("Pool",)),
        ]

        result = get_mutable_shared_param_types("test::get_fee", facts)

        assert len(result) == 0

    def test_ignores_mut_non_shared(self):
        """Mutable reference to non-shared object is not flagged."""
        facts = [
            Fact("FormalArg", ("test::update", 0, "record", "&mut UserRecord")),
            # UserRecord is not shared
        ]

        result = get_mutable_shared_param_types("test::update", facts)

        assert len(result) == 0

    def test_handles_generic_types(self):
        """Generic types like Pool<T> are matched correctly."""
        facts = [
            Fact("FormalArg", ("test::set_rate", 0, "pool", "&mut Pool<USDC>")),
            Fact("IsSharedObject", ("Pool",)),
        ]

        result = get_mutable_shared_param_types("test::set_rate", facts)

        assert "Pool" in result

    def test_handles_qualified_names(self):
        """Qualified names like module::Pool are matched."""
        facts = [
            Fact("FormalArg", ("test::configure", 0, "config", "&mut amm::Config")),
            Fact("IsSharedObject", ("amm::Config",)),
        ]

        result = get_mutable_shared_param_types("test::configure", facts)

        assert "amm::Config" in result

    def test_matches_simple_to_qualified(self):
        """Simple name matches qualified IsSharedObject."""
        facts = [
            Fact("FormalArg", ("test::set_admin", 0, "registry", "&mut Registry")),
            Fact("IsSharedObject", ("protocol::Registry",)),
        ]

        result = get_mutable_shared_param_types("test::set_admin", facts)

        assert "Registry" in result


class TestSensitiveSetterClassification:
    """Test LLM classification for sensitive setters."""

    def test_protocol_config_setter_is_vulnerable(self):
        """Function that modifies protocol config without auth is vulnerable."""
        facts = [
            Fact("Fun", ("test::set_fee_rate",)),
            Fact("IsPublic", ("test::set_fee_rate",)),
            Fact("FormalArg", ("test::set_fee_rate", 0, "pool", "&mut Pool")),
            Fact("FormalArg", ("test::set_fee_rate", 1, "new_rate", "u64")),
            Fact("IsSharedObject", ("Pool",)),
        ]
        source = """
module test {
    struct Pool has key {
        id: UID,
        fee_rate: u64,  // Protocol fee rate for all swaps
        total_liquidity: u64,
    }

    public fun set_fee_rate(pool: &mut Pool, new_rate: u64) {
        pool.fee_rate = new_rate;
    }
}
"""

        with patch("semantic.llm_facts.call_llm_json") as mock_llm:
            mock_llm.return_value = {
                "has_access_control": False,
                "modifies_protocol_config": True,
                "modifies_user_owned_state": False,
                "reason": "Sets fee_rate which affects all protocol users",
            }

            is_vulnerable = generate_sensitive_setter_fact(
                func_name="test::set_fee_rate",
                file_path="test.move",
                facts=facts,
                source_code=source,
                root=None,
                ctx=None,
            )

            assert is_vulnerable is True
            # Should add LLMSensitiveSetter fact
            assert any(f.name == "LLMSensitiveSetter" and f.args[0] == "test::set_fee_rate" for f in facts)

    def test_user_state_setter_is_safe(self):
        """Function that modifies user's own state is safe."""
        facts = [
            Fact("Fun", ("test::update_position",)),
            Fact("IsPublic", ("test::update_position",)),
            Fact("FormalArg", ("test::update_position", 0, "registry", "&mut Registry")),
            Fact("FormalArg", ("test::update_position", 1, "user", "address")),
            Fact("FormalArg", ("test::update_position", 2, "amount", "u64")),
            Fact("IsSharedObject", ("Registry",)),
        ]
        source = """
module test {
    struct Registry has key {
        id: UID,
        positions: Table<address, Position>,
    }

    public fun update_position(registry: &mut Registry, user: address, amount: u64) {
        let pos = table::borrow_mut(&mut registry.positions, user);
        pos.amount = amount;
    }
}
"""

        with patch("semantic.llm_facts.call_llm_json") as mock_llm:
            mock_llm.return_value = {
                "has_access_control": False,
                "modifies_protocol_config": False,
                "modifies_user_owned_state": True,
                "reason": "Updates user's own position in registry",
            }

            is_vulnerable = generate_sensitive_setter_fact(
                func_name="test::update_position",
                file_path="test.move",
                facts=facts,
                source_code=source,
                root=None,
                ctx=None,
            )

            assert is_vulnerable is False
            # Should add LLMHasSetterAuth fact
            assert any(f.name == "LLMHasSetterAuth" and f.args[0] == "test::update_position" for f in facts)

    def test_no_shared_param_returns_safe(self):
        """Function without mutable shared params returns safe without LLM call."""
        facts = [
            Fact("Fun", ("test::update_local",)),
            Fact("IsPublic", ("test::update_local",)),
            Fact("FormalArg", ("test::update_local", 0, "record", "&mut Record")),
            # Record is not in IsSharedObject
        ]
        source = "module test { public fun update_local(record: &mut Record) {} }"

        with patch("semantic.llm_facts.call_llm_json") as mock_llm:
            is_vulnerable = generate_sensitive_setter_fact(
                func_name="test::update_local",
                file_path="test.move",
                facts=facts,
                source_code=source,
                root=None,
                ctx=None,
            )

            # Should not call LLM
            mock_llm.assert_not_called()
            assert is_vulnerable is False
            # Should still add LLMHasSetterAuth fact
            assert any(f.name == "LLMHasSetterAuth" and f.args[0] == "test::update_local" for f in facts)


class TestSensitiveSetterPrompt:
    """Test prompt building for sensitive setter classification."""

    def test_prompt_includes_task_section(self):
        """Prompt should include the task section for LLM."""
        import tempfile

        facts = [
            Fact("Fun", ("test::set_admin_prompt",)),
            Fact("IsPublic", ("test::set_admin_prompt",)),
            Fact("IsEntry", ("test::set_admin_prompt",)),
            Fact("FormalArg", ("test::set_admin_prompt", 0, "config", "&mut Config")),
            Fact("FormalArg", ("test::set_admin_prompt", 1, "new_admin", "address")),
            Fact("IsSharedObject", ("Config",)),
        ]
        source = """
module test {
    struct Config has key {
        id: UID,
        admin: address,
    }

    public entry fun set_admin_prompt(config: &mut Config, new_admin: address) {
        config.admin = new_admin;
    }
}
"""
        # Use temp cache dir to avoid hitting existing cache
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("llm.cache.sensitive_setter_cache.cache_dir", tmpdir):
                with patch("semantic.llm_facts.call_llm_json") as mock_llm:
                    mock_llm.return_value = {
                        "has_access_control": False,
                        "modifies_protocol_config": True,
                        "modifies_user_owned_state": False,
                    }

                    generate_sensitive_setter_fact(
                        func_name="test::set_admin_prompt",
                        file_path="test.move",
                        facts=facts,
                        source_code=source,
                        root=None,  # No AST root - struct extraction will fail gracefully
                        ctx=None,
                    )

                    # LLM should have been called
                    assert mock_llm.called, "LLM should have been called"

                    # Check prompt content
                    call_args = mock_llm.call_args
                    prompt = call_args[0][0]

                    # Prompt should include the task and key question
                    assert "TASK" in prompt
                    assert "VULNERABLE" in prompt
                    assert "SAFE" in prompt
                    assert "protocol" in prompt.lower()
                    assert "admin auth" in prompt.lower() or "authorization" in prompt.lower()


class TestSensitiveSetterCaching:
    """Test caching behavior for sensitive setter classification."""

    def test_result_is_cached(self):
        """Successful classification should be cached."""
        import tempfile

        facts = [
            Fact("Fun", ("test::cached_func",)),
            Fact("IsPublic", ("test::cached_func",)),
            Fact("FormalArg", ("test::cached_func", 0, "pool", "&mut Pool")),
            Fact("IsSharedObject", ("Pool",)),
        ]
        source = "module test { struct Pool has key { id: UID } public fun cached_func(pool: &mut Pool) {} }"

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("llm.cache.sensitive_setter_cache.cache_dir", tmpdir):
                with patch("semantic.llm_facts.call_llm_json") as mock_llm:
                    mock_llm.return_value = {
                        "has_access_control": False,
                        "modifies_protocol_config": True,
                        "modifies_user_owned_state": False,
                    }

                    # First call
                    generate_sensitive_setter_fact(
                        func_name="test::cached_func",
                        file_path="test.move",
                        facts=facts,
                        source_code=source,
                        root=None,
                        ctx=None,
                    )

                    # Second call should use cache
                    generate_sensitive_setter_fact(
                        func_name="test::cached_func",
                        file_path="test.move",
                        facts=facts,
                        source_code=source,
                        root=None,
                        ctx=None,
                    )

                    # LLM should only be called once
                    assert mock_llm.call_count == 1

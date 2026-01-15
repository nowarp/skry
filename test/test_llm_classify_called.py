"""Tests for LLM classification fact generation.

These tests verify that:
1. The correct facts are added when LLM returns vulnerable/safe
2. Pre-filters work correctly (no LLM call when filtered)
"""

from unittest.mock import patch

from core.facts import Fact
from semantic.llm_facts import generate_access_control_fact, generate_sensitive_setter_fact


class TestAccessControlFactGeneration:
    """Test fact generation for access control classification."""

    def test_vulnerable_fact_added_for_unprotected_entry(self):
        """Entry function with sink and no auth should be marked vulnerable."""
        facts = [
            Fact("Fun", ("test::withdraw",)),
            Fact("IsPublic", ("test::withdraw",)),
            Fact("IsEntry", ("test::withdraw",)),
            Fact("TransferSink", ("test::withdraw", "transfer@1", "transfer::transfer")),
        ]
        source = "module test { public entry fun withdraw() {} }"

        with patch("semantic.llm_facts.call_llm_json") as mock_llm:
            mock_llm.return_value = {
                "has_access_control": False,
                "is_vulnerable": True,
                "reason": "No auth check before transfer",
            }

            result = generate_access_control_fact(
                func_name="test::withdraw",
                file_path="test.move",
                facts=facts,
                source_code=source,
                root=None,
                ctx=None,
            )

            assert result is True  # vulnerable
            vuln_facts = [f for f in facts if f.name == "LLMVulnerableAccessControl"]
            assert len(vuln_facts) == 1
            assert vuln_facts[0].args[0] == "test::withdraw"

    def test_safe_fact_added_when_has_access_control(self):
        """Function with access control should get safe fact."""
        facts = [
            Fact("Fun", ("test::admin_withdraw",)),
            Fact("IsEntry", ("test::admin_withdraw",)),
            Fact("TransferSink", ("test::admin_withdraw", "transfer@1", "transfer::transfer")),
        ]
        source = "module test { public entry fun admin_withdraw(admin: &AdminCap) {} }"

        with patch("semantic.llm_facts.call_llm_json") as mock_llm:
            mock_llm.return_value = {
                "has_access_control": True,
                "is_vulnerable": False,
                "reason": "Has AdminCap parameter",
            }

            result = generate_access_control_fact(
                func_name="test::admin_withdraw",
                file_path="test.move",
                facts=facts,
                source_code=source,
                root=None,
                ctx=None,
            )

            assert result is False  # not vulnerable
            safe_facts = [f for f in facts if f.name == "LLMHasAccessControl"]
            assert len(safe_facts) == 1


class TestSensitiveSetterFactGeneration:
    """Test fact generation for sensitive setter classification."""

    def test_vulnerable_setter_fact_added(self):
        """Protocol config setter without auth should be marked vulnerable."""
        facts = [
            Fact("Fun", ("test::set_fee",)),
            Fact("IsPublic", ("test::set_fee",)),
            Fact("FormalArg", ("test::set_fee", 0, "config", "&mut Config")),
            Fact("IsSharedObject", ("Config",)),
        ]
        source = "module test { public fun set_fee(config: &mut Config, new_fee: u64) { config.fee = new_fee; } }"

        with patch("semantic.llm_facts.call_llm_json") as mock_llm:
            mock_llm.return_value = {
                "has_access_control": False,
                "modifies_protocol_config": True,
                "modifies_user_owned_state": False,
            }

            result = generate_sensitive_setter_fact(
                func_name="test::set_fee",
                file_path="test.move",
                facts=facts,
                source_code=source,
                root=None,
                ctx=None,
            )

            assert result is True  # vulnerable
            vuln_facts = [f for f in facts if f.name == "LLMSensitiveSetter"]
            assert len(vuln_facts) == 1

    def test_no_shared_object_skips_llm(self):
        """Function without mutable shared param skips LLM (optimization)."""
        facts = [
            Fact("Fun", ("test::update_record",)),
            Fact("IsPublic", ("test::update_record",)),
            Fact("FormalArg", ("test::update_record", 0, "record", "&mut UserRecord")),
            # UserRecord is NOT in IsSharedObject facts
        ]
        source = "module test { public fun update_record(record: &mut UserRecord) {} }"

        with patch("semantic.llm_facts.call_llm_json") as mock_llm:
            result = generate_sensitive_setter_fact(
                func_name="test::update_record",
                file_path="test.move",
                facts=facts,
                source_code=source,
                root=None,
                ctx=None,
            )

            # LLM should NOT be called - no mutable shared params
            mock_llm.assert_not_called()
            assert result is False
            # Should still add safe fact
            safe_facts = [f for f in facts if f.name == "LLMHasSetterAuth"]
            assert len(safe_facts) == 1



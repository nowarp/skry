"""End-to-end tests using real Move code fixtures.

Tests the full analysis pipeline on realistic examples
and verifies expected violations are detected.

Running E2E Tests:
------------------
1. Structural-only tests (no LLM):
   pytest test/test_e2e.py -v

2. Full tests with LLM cache:
   SKRY_LLM_MODE=cached pytest test/test_e2e.py -v

   Requires pre-built cache in .skry_cache/
   Generate with: SKRY_SAVE_CACHE=1 python main.py <project>

Injecting LLM Facts:
--------------------
For tests that require LLM-generated facts (e.g., IsConfig, FeaturePause),
use the `inject_facts` parameter to simulate LLM output:

    result = _run_analysis(
        files,
        "config-write-without-privileged",
        inject_facts={
            "project": [Fact("IsConfig", ("ProtocolConfig",))],
            "file": [Fact("ChecksPause", ("check_pause",))],
        }
    )
"""

import os
from pathlib import Path
from typing import List, Tuple, NamedTuple, Dict, Optional

import pytest

from core.context import ProjectContext
from core.facts import Fact
from analysis import run_structural_analysis, run_fact_propagation
from rules.hy_loader import load_hy_rules
from pipeline import run_filter_pass
from taint.guards import generate_guarded_sink_facts


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "e2e"
RULES_DIR = Path(__file__).parent.parent / "rules"


class AnalysisResult(NamedTuple):
    """Result of e2e analysis."""
    violations: List[Tuple[str, str, str]]  # (rule, func, file)
    candidates: List[Tuple[str, str, str]]  # (rule, func, file) - treated as violations in tests


def _load_all_rules():
    """Load all rules from rules/*.hy files."""
    rules = []
    for rule_file in RULES_DIR.glob("*.hy"):
        rules.extend(load_hy_rules(str(rule_file)))
    return rules


def _run_analysis(
    source_files: List[str],
    rule_filter: str = None,
    inject_facts: Optional[Dict[str, List[Fact]]] = None,
) -> AnalysisResult:
    """
    Run full analysis pipeline on source files.

    Args:
        source_files: List of .move file paths
        rule_filter: Optional rule name to filter (e.g., "missing-authorization")
        inject_facts: Optional dict to inject facts that simulate LLM output:
            - "project": List of project-level facts (e.g., FeaturePause, IsConfig)
            - "file": List of per-file facts added to ALL source files

    Returns:
        AnalysisResult with violations (filter-only) and candidates (needs LLM)
    """
    ctx = ProjectContext(source_files)
    run_structural_analysis(ctx)
    run_fact_propagation(ctx)

    # Inject simulated LLM facts if provided (BEFORE generating guarded sink facts)
    if inject_facts:
        # Semantic facts (e.g., IsUserAsset, IsPrivileged) - injected BEFORE user asset detection
        # Must be injected before run_fact_propagation to affect WritesUserAsset generation
        if "semantic" in inject_facts:
            ctx.semantic_facts.extend(inject_facts["semantic"])
            # Re-run user asset detection to generate WritesUserAsset facts
            from analysis.user_assets import detect_user_asset_containers
            detect_user_asset_containers(ctx)

        # Project-level facts (e.g., FeaturePause, IsConfig)
        if "project" in inject_facts:
            ctx.project_facts.extend(inject_facts["project"])

        # Per-file facts (added to all source files)
        if "file" in inject_facts:
            for file_ctx in ctx.source_files.values():
                file_ctx.facts.extend(inject_facts["file"])

    # Generate guarded sink facts (needs ChecksPause etc to be present)
    generate_guarded_sink_facts(ctx)

    # Load rules
    rules = _load_all_rules()
    if rule_filter:
        rules = [r for r in rules if r.name == rule_filter]

    # Run filter pass (structural violations)
    filter_result = run_filter_pass(ctx, rules)

    def extract_results(items):
        """Extract (rule, entity, file) tuples from violations or candidates."""
        results = []
        for item in items:
            # Handle both (rule, binding) tuples and Candidate objects
            if hasattr(item, 'rule'):
                rule = item.rule
                binding = item.binding
            else:
                rule, binding = item
            entity_name = binding.get(rule.match_binding, "unknown")
            file_path = "unknown"
            for fp, file_ctx in ctx.source_files.items():
                if rule.match_pattern == "fun" and any(f.name == "Fun" and f.args[0] == entity_name for f in file_ctx.facts):
                    file_path = fp
                    break
                elif rule.match_pattern == "role" and any(f.name == "Struct" and f.args[0] == entity_name for f in file_ctx.facts):
                    file_path = fp
                    break
                elif rule.match_pattern == "event" and any(f.name == "IsEvent" and f.args[0] == entity_name for f in file_ctx.facts):
                    file_path = fp
                    break
            results.append((rule.name, entity_name, file_path))
        return results

    # Separate violations and candidates (candidates are treated as violations in tests)
    violations = extract_results(filter_result.violations)
    candidates = extract_results(filter_result.candidates)
    return AnalysisResult(violations=violations, candidates=candidates)


def _get_fixture_files(*paths: str) -> List[str]:
    """Get absolute paths for fixture files."""
    return [str(FIXTURES_DIR / p) for p in paths]


class TestDrainVulnerability:
    """Test drain vulnerability detection (arbitrary-recipient-drain rule)."""

    def test_detects_direct_drain(self):
        """Direct drain from shared pool should be flagged."""
        files = _get_fixture_files("arbitrary-recipient-drain/drain.move")
        result = _run_analysis(files, "arbitrary-recipient-drain")

        func_names = {v[1] for v in result.violations}
        assert "test::vulnerable_pool::drain" in func_names, \
            f"Expected drain to be flagged: {result.violations}"

    def test_detects_cross_function_drain(self):
        """Drain via helper function should be flagged.

        Tests interprocedural analysis: entry_drain calls do_drain which has
        the actual sink. TaintedTransferRecipient should propagate to entry_drain.
        """
        files = _get_fixture_files("arbitrary-recipient-drain/cross_drain.move")

        if not os.path.exists(files[0]):
            pytest.skip("cross_drain.move fixture not yet created")

        result = _run_analysis(files, "arbitrary-recipient-drain")

        func_names = {v[1] for v in result.violations}
        # Entry function should be flagged (sink is in callee)
        assert "test::cross_drain::entry_drain" in func_names, \
            f"Expected entry_drain to be flagged: {result.violations}"

    # ========== Safe Pattern Tests ==========

    def test_safe_with_role(self):
        """Withdraw with AdminCap should NOT be flagged (checks-role?)."""
        files = _get_fixture_files("arbitrary-recipient-drain/safe_patterns.move")
        result = _run_analysis(files, "arbitrary-recipient-drain")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("withdraw_with_admin" in fn for fn in all_funcs), \
            f"withdraw_with_admin should NOT be flagged: {all_funcs}"

    def test_safe_sender_equality_check(self):
        """Withdraw with sender equality check should NOT be flagged (has-sender-equality-check?)."""
        files = _get_fixture_files("arbitrary-recipient-drain/safe_patterns.move")
        result = _run_analysis(files, "arbitrary-recipient-drain")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("withdraw_owned" in fn for fn in all_funcs), \
            f"withdraw_owned should NOT be flagged: {all_funcs}"

    def test_safe_user_provided_value(self):
        """Transfer of user-provided Coin should NOT be flagged (transfers-user-provided-value?)."""
        files = _get_fixture_files("arbitrary-recipient-drain/safe_patterns.move")
        result = _run_analysis(files, "arbitrary-recipient-drain")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("transfer_my_coin" in fn for fn in all_funcs), \
            f"transfer_my_coin should NOT be flagged: {all_funcs}"

    def test_safe_operates_on_owned_only(self):
        """Function on owned objects should NOT be flagged (operates-on-owned-only?)."""
        files = _get_fixture_files("arbitrary-recipient-drain/safe_patterns.move")
        result = _run_analysis(files, "arbitrary-recipient-drain")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("withdraw_from_owned_vault" in fn for fn in all_funcs), \
            f"withdraw_from_owned_vault should NOT be flagged: {all_funcs}"

    def test_safe_user_creatable_struct(self):
        """Transfer of user-creatable struct should NOT be flagged (user-creatable-struct?)."""
        files = _get_fixture_files("arbitrary-recipient-drain/safe_patterns.move")
        result = _run_analysis(files, "arbitrary-recipient-drain")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("transfer_receipt" in fn for fn in all_funcs), \
            f"transfer_receipt should NOT be flagged: {all_funcs}"

    def test_safe_transfers_from_sender(self):
        """Deposit of own funds should NOT be flagged (transfers-from-sender?)."""
        files = _get_fixture_files("arbitrary-recipient-drain/safe_patterns.move")
        result = _run_analysis(files, "arbitrary-recipient-drain")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("deposit_own_funds" in fn for fn in all_funcs), \
            f"deposit_own_funds should NOT be flagged: {all_funcs}"

    def test_safe_withdraws_from_caller_owned(self):
        """Withdraw from caller's vault should NOT be flagged (withdraws-from-caller-owned-pool?)."""
        files = _get_fixture_files("arbitrary-recipient-drain/safe_patterns.move")
        result = _run_analysis(files, "arbitrary-recipient-drain")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("withdraw_my_vault" in fn for fn in all_funcs), \
            f"withdraw_my_vault should NOT be flagged: {all_funcs}"


class TestMissingAuthorization:
    """Test missing authorization detection.

    Note: missing-authorization has :classify, so matches go to candidates.
    """

    def test_detects_unsafe_withdraw(self):
        """Withdraw without role check should be flagged as candidate."""
        files = _get_fixture_files(
            "missing-authorization/ac1_config.move",
            "missing-authorization/ac1_withdraw.move",
        )
        result = _run_analysis(files, "missing-authorization")

        func_names = {c[1] for c in result.candidates}
        # withdraw_unsafe has no AdminCap param
        assert any("withdraw_unsafe" in fn for fn in func_names), \
            f"Expected withdraw_unsafe to be a candidate: {result.candidates}"

    def test_safe_withdraw_not_flagged(self):
        """Withdraw with AdminCap should NOT be flagged."""
        files = _get_fixture_files(
            "missing-authorization/ac1_config.move",
            "missing-authorization/ac1_withdraw.move",
        )
        result = _run_analysis(files, "missing-authorization")

        # Check both violations and candidates
        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # withdraw_safe has AdminCap param
        assert not any("withdraw_safe" in fn for fn in all_funcs), \
            f"withdraw_safe should NOT be flagged: violations={result.violations}, candidates={result.candidates}"


class TestChecksCapability:
    """Test role-based access control detection."""

    def test_multiple_role_types(self):
        """Both AdminCap and OperatorCap should protect functions."""
        files = _get_fixture_files(
            "missing-authorization/checks_role_admin.move",
            "missing-authorization/checks_role_treasury.move",
        )
        result = _run_analysis(files, "missing-authorization")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}

        # withdraw_unsafe should be flagged
        assert any("withdraw_unsafe" in fn for fn in all_funcs), \
            f"Expected withdraw_unsafe to be flagged: {result}"

        # withdraw_with_admin and withdraw_with_operator should NOT be flagged
        assert not any("withdraw_with_admin" in fn for fn in all_funcs), \
            f"withdraw_with_admin should NOT be flagged: {result}"
        assert not any("withdraw_with_operator" in fn for fn in all_funcs), \
            f"withdraw_with_operator should NOT be flagged: {result}"


class TestUnprotectedMint:
    """Test unprotected mint/transfer detection."""

    def test_unprotected_send(self):
        """Unprotected mint_and_transfer should be flagged."""
        files = _get_fixture_files("_infrastructure/unprotected_send.move")

        if not os.path.exists(files[0]):
            pytest.skip("unprotected_send.move fixture not yet created")

        result = _run_analysis(files, "missing-authorization")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("unprotected_send" in fn for fn in all_funcs), \
            f"Expected unprotected_send to be flagged: {result}"


class TestVulnerableFeePool:
    """Test vulnerable fee pool detection."""

    def test_fee_pool_drain(self):
        """Vulnerable fee pool should be detected."""
        files = _get_fixture_files("_infrastructure/vulnerable_fee_pool/sources/pool.move")

        # Check if file exists
        assert os.path.exists(files[0]), f"Fixture not found: {files[0]}"

        result = _run_analysis(files)

        # Should have some violations or candidates
        # Just verify analysis doesn't crash for now
        assert isinstance(result.violations, list)
        assert isinstance(result.candidates, list)


class TestCrossModuleGuardPropagation:
    """Test that guards propagate correctly across module boundaries.

    Critical for IPA correctness: if callee has auth check, caller should
    inherit the guard and NOT be flagged.
    """

    def test_unguarded_callee_flagged(self):
        """Entry calling unguarded helper should be flagged."""
        files = _get_fixture_files(
            "missing-authorization/cross_module_entry.move",
            "missing-authorization/cross_module_guarded_helper.move",
            "missing-authorization/cross_module_unguarded_helper.move",
        )
        result = _run_analysis(files, "missing-authorization")

        # withdraw_via_unguarded calls unguarded helper - should be candidate
        func_names = {c[1] for c in result.candidates}
        assert any("withdraw_via_unguarded" in fn for fn in func_names), \
            f"Expected withdraw_via_unguarded to be flagged: {result.candidates}"

    def test_guarded_callee_not_flagged(self):
        """Entry calling guarded helper should NOT be flagged (guard propagates)."""
        files = _get_fixture_files(
            "missing-authorization/cross_module_entry.move",
            "missing-authorization/cross_module_guarded_helper.move",
            "missing-authorization/cross_module_unguarded_helper.move",
        )
        result = _run_analysis(files, "missing-authorization")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # withdraw_via_guarded calls helper with sender equality check - should NOT be flagged
        assert not any("withdraw_via_guarded" in fn for fn in all_funcs), \
            f"withdraw_via_guarded should NOT be flagged (guard propagates): {all_funcs}"

    def test_entry_with_role_not_flagged(self):
        """Entry with its own role check should NOT be flagged."""
        files = _get_fixture_files(
            "missing-authorization/cross_module_entry.move",
            "missing-authorization/cross_module_guarded_helper.move",
            "missing-authorization/cross_module_unguarded_helper.move",
        )
        result = _run_analysis(files, "missing-authorization")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # withdraw_with_role has AdminCap param - should NOT be flagged
        assert not any("withdraw_with_role" in fn for fn in all_funcs), \
            f"withdraw_with_role should NOT be flagged (has role): {all_funcs}"


class TestTaintedAmountDrain:
    """Test tainted-amount-drain rule.

    Detects user-controlled amount in coin::take enabling drain.
    """

    def test_direct_amount_drain(self):
        """Direct tainted amount should be flagged."""
        files = _get_fixture_files("tainted-amount-drain/vulnerable.move")
        result = _run_analysis(files, "tainted-amount-drain")

        # drain_direct has tainted amount, no role check
        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("drain_direct" in fn for fn in all_funcs), \
            f"Expected drain_direct to be flagged: {all_funcs}"

    def test_ipa_amount_drain(self):
        """Entry calling helper with tainted amount should be flagged."""
        files = _get_fixture_files("tainted-amount-drain/vulnerable.move")
        result = _run_analysis(files, "tainted-amount-drain")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("drain_via_helper" in fn for fn in all_funcs), \
            f"Expected drain_via_helper to be flagged: {all_funcs}"

    def test_safe_with_role(self):
        """Entry with role check should NOT be flagged."""
        files = _get_fixture_files("tainted-amount-drain/vulnerable.move")
        result = _run_analysis(files, "tainted-amount-drain")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("drain_with_role" in fn for fn in all_funcs), \
            f"drain_with_role should NOT be flagged: {all_funcs}"

    def test_ipa_callee_has_role(self):
        """Entry calling guarded helper should NOT be flagged (guard propagates)."""
        files = _get_fixture_files("tainted-amount-drain/vulnerable.move")
        result = _run_analysis(files, "tainted-amount-drain")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("drain_via_guarded_helper" in fn for fn in all_funcs), \
            f"drain_via_guarded_helper should NOT be flagged: {all_funcs}"

    def test_cross_module_amount_drain(self):
        """Cross-module tainted amount should be flagged."""
        files = _get_fixture_files(
            "tainted-amount-drain/cross_module_entry.move",
            "tainted-amount-drain/cross_module_helper.move",
        )
        result = _run_analysis(files, "tainted-amount-drain")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("drain_cross_module" in fn for fn in all_funcs), \
            f"Expected drain_cross_module to be flagged: {all_funcs}"

    def test_cross_module_guarded_not_flagged(self):
        """Cross-module with guarded callee should NOT be flagged."""
        files = _get_fixture_files(
            "tainted-amount-drain/cross_module_entry.move",
            "tainted-amount-drain/cross_module_helper.move",
        )
        result = _run_analysis(files, "tainted-amount-drain")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("drain_cross_module_guarded" in fn for fn in all_funcs), \
            f"drain_cross_module_guarded should NOT be flagged: {all_funcs}"

    def test_transfer_to_sender_not_flagged(self):
        """Functions that transfer extracted value TO SENDER should NOT be flagged.

        Pattern: let user = tx_context::sender(ctx); transfer::public_transfer(coins, user);

        This is safe because the caller can only affect themselves, not drain to an arbitrary
        recipient. Examples: lending withdraw, borrow operations.
        """
        files = _get_fixture_files("tainted-amount-drain/transfer_to_sender.move")
        result = _run_analysis(files, "tainted-amount-drain")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}

        # These should NOT be flagged - they transfer to sender
        assert not any("entry_withdraw" in fn and "v2" not in fn for fn in all_funcs), \
            f"entry_withdraw should NOT be flagged (transfers to sender): {all_funcs}"
        assert not any("entry_withdraw_v2" in fn for fn in all_funcs), \
            f"entry_withdraw_v2 should NOT be flagged (transfers to sender): {all_funcs}"
        assert not any("entry_borrow" in fn for fn in all_funcs), \
            f"entry_borrow should NOT be flagged (transfers to sender): {all_funcs}"

    def test_drain_to_arbitrary_recipient_flagged(self):
        """Functions that transfer to arbitrary recipient SHOULD be flagged."""
        files = _get_fixture_files("tainted-amount-drain/transfer_to_sender.move")
        result = _run_analysis(files, "tainted-amount-drain")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}

        # This SHOULD be flagged - transfers to arbitrary recipient
        assert any("drain_to_arbitrary" in fn for fn in all_funcs), \
            f"Expected drain_to_arbitrary to be flagged: {all_funcs}"


class TestTaintedStateModification:
    """Test tainted-state-modification rule.

    Detects user-controlled data written to state without authorization.
    Uses per-sink guard: has-unguarded-state-write-no-auth?

    Note: This rule detects state writes through function calls (dynamic_field::add, etc.),
    not direct field assignments.
    """

    def test_direct_state_write(self):
        """Direct tainted state write via dynamic_field should be flagged."""
        files = _get_fixture_files("tainted-state-modification/vulnerable.move")
        result = _run_analysis(files, "tainted-state-modification")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("set_value_unsafe" in fn for fn in all_funcs), \
            f"Expected set_value_unsafe to be flagged: {all_funcs}"

    def test_tainted_data_write(self):
        """Tainted vector data written to state should be flagged."""
        files = _get_fixture_files("tainted-state-modification/vulnerable.move")
        result = _run_analysis(files, "tainted-state-modification")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("set_data_unsafe" in fn for fn in all_funcs), \
            f"Expected set_data_unsafe to be flagged: {all_funcs}"

    def test_ipa_state_write(self):
        """Entry calling helper that writes state should be flagged."""
        files = _get_fixture_files("tainted-state-modification/vulnerable.move")
        result = _run_analysis(files, "tainted-state-modification")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("set_value_via_helper" in fn for fn in all_funcs), \
            f"Expected set_value_via_helper to be flagged: {all_funcs}"

    def test_safe_with_sender(self):
        """Entry with sender check should NOT be flagged."""
        files = _get_fixture_files("tainted-state-modification/vulnerable.move")
        result = _run_analysis(files, "tainted-state-modification")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("set_value_with_sender" in fn for fn in all_funcs), \
            f"set_value_with_sender should NOT be flagged: {all_funcs}"

    def test_safe_with_role(self):
        """Entry with role check should NOT be flagged."""
        files = _get_fixture_files("tainted-state-modification/vulnerable.move")
        result = _run_analysis(files, "tainted-state-modification")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("set_value_with_role" in fn for fn in all_funcs), \
            f"set_value_with_role should NOT be flagged: {all_funcs}"

    def test_ipa_callee_checks_sender(self):
        """Entry calling guarded helper should NOT be flagged (guard propagates)."""
        files = _get_fixture_files("tainted-state-modification/vulnerable.move")
        result = _run_analysis(files, "tainted-state-modification")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("set_value_via_guarded_helper" in fn for fn in all_funcs), \
            f"set_value_via_guarded_helper should NOT be flagged: {all_funcs}"

    def test_let_stmt_state_write_sink(self):
        """State write via let binding (table::borrow_mut) should be flagged."""
        files = _get_fixture_files("tainted-state-modification/vulnerable.move")
        result = _run_analysis(files, "tainted-state-modification")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("modify_registry_unsafe" in fn for fn in all_funcs), \
            f"Expected modify_registry_unsafe to be flagged: {all_funcs}"


class TestConfigWriteWithoutAdmin:
    """Test config-write-without-privileged rule.

    Detects modification of protocol config struct without admin authorization.
    This rule requires IsConfig facts - we inject them to simulate LLM classification.
    """

    # Inject IsConfig fact for ProtocolConfig struct
    CONFIG_FACTS = {
        "file": [Fact("IsConfig", ("test::config_write::ProtocolConfig",))]
    }

    def test_direct_config_write(self):
        """Direct config modification without admin should be flagged."""
        files = _get_fixture_files("config-write-without-privileged/vulnerable.move")
        result = _run_analysis(files, "config-write-without-privileged", inject_facts=self.CONFIG_FACTS)

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("set_fee" in fn and "admin" not in fn and "sender" not in fn
                   and "internal" not in fn for fn in all_funcs), \
            f"Expected set_fee to be flagged: {all_funcs}"

    def test_config_oracle_write(self):
        """Config oracle modification without admin should be flagged."""
        files = _get_fixture_files("config-write-without-privileged/vulnerable.move")
        result = _run_analysis(files, "config-write-without-privileged", inject_facts=self.CONFIG_FACTS)

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("set_oracle" in fn for fn in all_funcs), \
            f"Expected set_oracle to be flagged: {all_funcs}"

    def test_safe_with_role(self):
        """Config setter with admin role should NOT be flagged."""
        files = _get_fixture_files("config-write-without-privileged/vulnerable.move")
        result = _run_analysis(files, "config-write-without-privileged", inject_facts=self.CONFIG_FACTS)

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("set_fee_admin" in fn for fn in all_funcs), \
            f"set_fee_admin should NOT be flagged: {all_funcs}"

    def test_safe_with_sender(self):
        """Config setter with sender check should NOT be flagged."""
        files = _get_fixture_files("config-write-without-privileged/vulnerable.move")
        result = _run_analysis(files, "config-write-without-privileged", inject_facts=self.CONFIG_FACTS)

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("set_fee_with_sender" in fn for fn in all_funcs), \
            f"set_fee_with_sender should NOT be flagged: {all_funcs}"

    def test_safe_friend(self):
        """public(package) config setter should NOT be flagged."""
        files = _get_fixture_files("config-write-without-privileged/vulnerable.move")
        result = _run_analysis(files, "config-write-without-privileged", inject_facts=self.CONFIG_FACTS)

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("set_fee_internal" in fn for fn in all_funcs), \
            f"set_fee_internal should NOT be flagged: {all_funcs}"


class TestReturnsCoinWithoutAuth:
    """Test returns-coin-without-auth rule.

    Detects public functions returning Coin/Balance without authorization.
    This is a filter-only rule (no :classify clause).
    """

    def test_returns_coin_vulnerable(self):
        """Public function returning Coin without auth should be flagged."""
        files = _get_fixture_files("returns-coin-without-auth/vulnerable.move")
        result = _run_analysis(files, "returns-coin-without-auth")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("get_funds" in fn and "admin" not in fn and "sender" not in fn
                   and "internal" not in fn for fn in all_funcs), \
            f"Expected get_funds to be flagged: {all_funcs}"

    def test_safe_with_role(self):
        """Function with role check should NOT be flagged."""
        files = _get_fixture_files("returns-coin-without-auth/vulnerable.move")
        result = _run_analysis(files, "returns-coin-without-auth")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("get_funds_admin" in fn for fn in all_funcs), \
            f"get_funds_admin should NOT be flagged: {all_funcs}"

    def test_safe_with_sender(self):
        """Function with sender check should NOT be flagged."""
        files = _get_fixture_files("returns-coin-without-auth/vulnerable.move")
        result = _run_analysis(files, "returns-coin-without-auth")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("get_funds_with_sender" in fn for fn in all_funcs), \
            f"get_funds_with_sender should NOT be flagged: {all_funcs}"

    def test_safe_friend(self):
        """public(package) function should NOT be flagged."""
        files = _get_fixture_files("returns-coin-without-auth/vulnerable.move")
        result = _run_analysis(files, "returns-coin-without-auth")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("get_funds_internal" in fn for fn in all_funcs), \
            f"get_funds_internal should NOT be flagged: {all_funcs}"

    def test_ipa_returns_coin_vulnerable(self):
        """Entry returning Coin via helper should be flagged (IPA test)."""
        files = _get_fixture_files("returns-coin-without-auth/vulnerable.move")
        result = _run_analysis(files, "returns-coin-without-auth")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("get_funds_via_helper" in fn for fn in all_funcs), \
            f"Expected get_funds_via_helper to be flagged: {all_funcs}"

    def test_ipa_returns_coin_guarded_safe(self):
        """Entry with role calling helper should NOT be flagged (guard propagates)."""
        files = _get_fixture_files("returns-coin-without-auth/vulnerable.move")
        result = _run_analysis(files, "returns-coin-without-auth")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("get_funds_via_guarded_helper" in fn for fn in all_funcs), \
            f"get_funds_via_guarded_helper should NOT be flagged: {all_funcs}"

    def test_returns_balance_ref_safe(self):
        """Function returning &Balance<T> (immutable ref) should NOT be flagged."""
        files = _get_fixture_files("returns-coin-without-auth/vulnerable.move")
        result = _run_analysis(files, "returns-coin-without-auth")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # get_balance returns &Balance<SUI> which is safe
        assert not any("::get_balance" == fn or fn.endswith("::get_balance") for fn in all_funcs), \
            f"get_balance (immutable ref) should NOT be flagged: {all_funcs}"


class TestMutableRefEscape:
    """Test mutable-ref-escape rule.

    Detects public entry functions returning &mut reference to internal state.
    This is a filter-only rule (no :classify clause).
    """

    def test_returns_mutable_ref_vulnerable(self):
        """Public entry returning &mut to shared object should be flagged."""
        files = _get_fixture_files("mutable-ref-escape/vulnerable.move")
        result = _run_analysis(files, "mutable-ref-escape")

        # This is a filter-only rule, so check violations
        func_names = {v[1] for v in result.violations}
        assert any("get_balance_mut" in fn for fn in func_names), \
            f"Expected get_balance_mut to be flagged: {result.violations}"

    def test_returns_mutable_field_vulnerable(self):
        """Public entry returning &mut to internal field should be flagged."""
        files = _get_fixture_files("mutable-ref-escape/vulnerable.move")
        result = _run_analysis(files, "mutable-ref-escape")

        func_names = {v[1] for v in result.violations}
        assert any("get_fee_rate_mut" in fn for fn in func_names), \
            f"Expected get_fee_rate_mut to be flagged: {result.violations}"

    def test_safe_with_role(self):
        """Function with role check should NOT be flagged."""
        files = _get_fixture_files("mutable-ref-escape/vulnerable.move")
        result = _run_analysis(files, "mutable-ref-escape")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("get_balance_admin" in fn for fn in all_funcs), \
            f"get_balance_admin should NOT be flagged: {all_funcs}"

    def test_safe_friend(self):
        """public(package) function should NOT be flagged."""
        files = _get_fixture_files("mutable-ref-escape/vulnerable.move")
        result = _run_analysis(files, "mutable-ref-escape")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("get_balance_internal" in fn for fn in all_funcs), \
            f"get_balance_internal should NOT be flagged: {all_funcs}"

    def test_ipa_ref_escape_vulnerable(self):
        """Entry returning &mut via helper should be flagged (IPA test)."""
        files = _get_fixture_files("mutable-ref-escape/vulnerable.move")
        result = _run_analysis(files, "mutable-ref-escape")

        func_names = {v[1] for v in result.violations}
        assert any("get_balance_via_helper" in fn for fn in func_names), \
            f"Expected get_balance_via_helper to be flagged: {result.violations}"

    def test_ipa_ref_escape_guarded_safe(self):
        """Entry with role calling helper should NOT be flagged (guard propagates)."""
        files = _get_fixture_files("mutable-ref-escape/vulnerable.move")
        result = _run_analysis(files, "mutable-ref-escape")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("get_balance_via_guarded_helper" in fn for fn in all_funcs), \
            f"get_balance_via_guarded_helper should NOT be flagged: {all_funcs}"


class TestUnauthSensitiveSetter:
    """Test unauth-sensitive-setter rule.

    Detects modification of shared protocol state without authorization.
    Different from missing-authorization: catches setters without transfer sinks.
    This rule has :classify, so matches go to candidates.
    """

    def test_direct_setter_vulnerable(self):
        """Public setter modifying shared object should be flagged."""
        files = _get_fixture_files("unauth-sensitive-setter/vulnerable.move")
        result = _run_analysis(files, "unauth-sensitive-setter")

        # Rule has :classify, check candidates
        func_names = {c[1] for c in result.candidates}
        assert any("set_fee" in fn and "admin" not in fn and "sender" not in fn
                   and "internal" not in fn for fn in func_names), \
            f"Expected set_fee to be flagged: {result.candidates}"

    def test_oracle_setter_vulnerable(self):
        """Public setter modifying address field should be flagged."""
        files = _get_fixture_files("unauth-sensitive-setter/vulnerable.move")
        result = _run_analysis(files, "unauth-sensitive-setter")

        func_names = {c[1] for c in result.candidates}
        assert any("set_oracle" in fn for fn in func_names), \
            f"Expected set_oracle to be flagged: {result.candidates}"

    def test_ipa_setter_vulnerable(self):
        """Entry calling helper that modifies shared object should be flagged."""
        files = _get_fixture_files("unauth-sensitive-setter/vulnerable.move")
        result = _run_analysis(files, "unauth-sensitive-setter")

        func_names = {c[1] for c in result.candidates}
        assert any("update_limit" in fn for fn in func_names), \
            f"Expected update_limit to be flagged: {result.candidates}"

    def test_safe_with_role(self):
        """Setter with role check should NOT be flagged."""
        files = _get_fixture_files("unauth-sensitive-setter/vulnerable.move")
        result = _run_analysis(files, "unauth-sensitive-setter")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("set_fee_admin" in fn for fn in all_funcs), \
            f"set_fee_admin should NOT be flagged: {all_funcs}"

    def test_safe_with_sender(self):
        """Setter with sender check should NOT be flagged."""
        files = _get_fixture_files("unauth-sensitive-setter/vulnerable.move")
        result = _run_analysis(files, "unauth-sensitive-setter")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("set_fee_with_sender" in fn for fn in all_funcs), \
            f"set_fee_with_sender should NOT be flagged: {all_funcs}"

    def test_safe_friend(self):
        """public(package) setter should NOT be flagged."""
        files = _get_fixture_files("unauth-sensitive-setter/vulnerable.move")
        result = _run_analysis(files, "unauth-sensitive-setter")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("set_fee_internal" in fn for fn in all_funcs), \
            f"set_fee_internal should NOT be flagged: {all_funcs}"


class TestPauseCheckMissing:
    """Test pause-check-missing rule.

    Detects sensitive operations that don't check global pause state.
    Requires FeaturePause and ChecksPause facts - we inject them.
    """

    # Inject pause-related facts to simulate LLM output
    PAUSE_FACTS = {
        "project": [
            Fact("FeaturePause", (True,)),
            Fact("IsGlobalPauseField", ("test::pause_protocol::Config", "paused")),
        ],
        "file": [
            # Functions that check pause (direct)
            Fact("ChecksPause", ("test::pause_protocol::withdraw_with_pause",)),
            Fact("ChecksPause", ("test::pause_protocol::admin_withdraw_with_pause",)),
            # Helper that checks pause (for IPA tests)
            Fact("ChecksPause", ("test::pause_protocol::do_withdraw_checked",)),
        ]
    }

    def test_no_pause_check_vulnerable(self):
        """Function with sink but no pause check should be flagged."""
        files = _get_fixture_files("pause-check-missing/vulnerable.move")
        result = _run_analysis(files, "pause-check-missing", inject_facts=self.PAUSE_FACTS)

        # Filter-only rule, check violations
        func_names = {v[1] for v in result.violations}
        assert any("withdraw_no_pause" in fn for fn in func_names), \
            f"Expected withdraw_no_pause to be flagged: {result.violations}"

    def test_with_pause_check_safe(self):
        """Function that checks pause should NOT be flagged."""
        files = _get_fixture_files("pause-check-missing/vulnerable.move")
        result = _run_analysis(files, "pause-check-missing", inject_facts=self.PAUSE_FACTS)

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("withdraw_with_pause" in fn for fn in all_funcs), \
            f"withdraw_with_pause should NOT be flagged: {all_funcs}"

    def test_admin_function_not_flagged(self):
        """Admin function should NOT be flagged by pause-check-missing (handled by admin-bypasses-pause)."""
        files = _get_fixture_files("pause-check-missing/vulnerable.move")
        result = _run_analysis(files, "pause-check-missing", inject_facts=self.PAUSE_FACTS)

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("admin_withdraw" in fn for fn in all_funcs), \
            f"Admin functions should NOT be flagged by pause-check-missing: {all_funcs}"

    def test_ipa_no_pause_check_vulnerable(self):
        """IPA: Entry calling helper with sink but no pause check should be flagged."""
        files = _get_fixture_files("pause-check-missing/vulnerable.move")
        result = _run_analysis(files, "pause-check-missing", inject_facts=self.PAUSE_FACTS)

        func_names = {v[1] for v in result.violations}
        assert any("ipa_withdraw_no_pause" in fn for fn in func_names), \
            f"Expected ipa_withdraw_no_pause to be flagged: {result.violations}"

    def test_ipa_with_pause_check_safe(self):
        """IPA: Entry calling helper that checks pause should NOT be flagged (guard propagates)."""
        files = _get_fixture_files("pause-check-missing/vulnerable.move")
        result = _run_analysis(files, "pause-check-missing", inject_facts=self.PAUSE_FACTS)

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("ipa_withdraw_with_pause" in fn for fn in all_funcs), \
            f"ipa_withdraw_with_pause should NOT be flagged (guard propagates): {all_funcs}"


class TestAdminBypassesPause:
    """Test admin-bypasses-pause rule.

    Detects admin functions that can operate during pause (centralization risk).
    Requires FeaturePause and ChecksPause facts - we inject them.
    """

    # Inject pause-related facts
    PAUSE_FACTS = {
        "project": [
            Fact("FeaturePause", (True,)),
            Fact("IsGlobalPauseField", ("test::pause_protocol::Config", "paused")),
        ],
        "file": [
            Fact("ChecksPause", ("test::pause_protocol::withdraw_with_pause",)),
            Fact("ChecksPause", ("test::pause_protocol::admin_withdraw_with_pause",)),
        ]
    }

    def test_admin_no_pause_flagged(self):
        """Admin function without pause check should be flagged (info severity)."""
        files = _get_fixture_files("admin-bypasses-pause/vulnerable.move")
        result = _run_analysis(files, "admin-bypasses-pause", inject_facts=self.PAUSE_FACTS)

        # Filter-only rule
        func_names = {v[1] for v in result.violations}
        assert any("admin_withdraw_no_pause" in fn for fn in func_names), \
            f"Expected admin_withdraw_no_pause to be flagged: {result.violations}"

    def test_admin_with_pause_safe(self):
        """Admin function that checks pause should NOT be flagged."""
        files = _get_fixture_files("admin-bypasses-pause/vulnerable.move")
        result = _run_analysis(files, "admin-bypasses-pause", inject_facts=self.PAUSE_FACTS)

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("admin_withdraw_with_pause" in fn for fn in all_funcs), \
            f"admin_withdraw_with_pause should NOT be flagged: {all_funcs}"


class TestUnprotectedPause:
    """Test unprotected-pause rule.

    Detects pause control functions without authorization.
    Requires FeaturePause and IsPauseControl facts - we inject them.
    """

    # Inject pause-related facts
    PAUSE_FACTS = {
        "project": [
            Fact("FeaturePause", (True,)),
            Fact("IsGlobalPauseField", ("test::pause_protocol::Config", "paused")),
            # Functions that control pause
            Fact("IsPauseControl", ("test::pause_protocol::pause_protocol",)),
            Fact("IsPauseControl", ("test::pause_protocol::unpause_protocol",)),
            Fact("IsPauseControl", ("test::pause_protocol::pause_admin",)),
            Fact("IsPauseControl", ("test::pause_protocol::unpause_admin",)),
        ],
    }

    def test_unprotected_pause_vulnerable(self):
        """Pause function without role check should be flagged."""
        files = _get_fixture_files("unprotected-pause/vulnerable.move")
        result = _run_analysis(files, "unprotected-pause", inject_facts=self.PAUSE_FACTS)

        func_names = {v[1] for v in result.violations}
        assert any("pause_protocol" in fn and "admin" not in fn for fn in func_names), \
            f"Expected pause_protocol to be flagged: {result.violations}"

    def test_unprotected_unpause_vulnerable(self):
        """Unpause function without role check should be flagged."""
        files = _get_fixture_files("unprotected-pause/vulnerable.move")
        result = _run_analysis(files, "unprotected-pause", inject_facts=self.PAUSE_FACTS)

        func_names = {v[1] for v in result.violations}
        assert any("unpause_protocol" in fn and "admin" not in fn for fn in func_names), \
            f"Expected unpause_protocol to be flagged: {result.violations}"

    def test_pause_with_role_safe(self):
        """Pause function with admin role should NOT be flagged."""
        files = _get_fixture_files("unprotected-pause/vulnerable.move")
        result = _run_analysis(files, "unprotected-pause", inject_facts=self.PAUSE_FACTS)

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("pause_admin" in fn for fn in all_funcs), \
            f"pause_admin should NOT be flagged: {all_funcs}"

    def test_unpause_with_role_safe(self):
        """Unpause function with admin role should NOT be flagged."""
        files = _get_fixture_files("unprotected-pause/vulnerable.move")
        result = _run_analysis(files, "unprotected-pause", inject_facts=self.PAUSE_FACTS)

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("unpause_admin" in fn for fn in all_funcs), \
            f"unpause_admin should NOT be flagged: {all_funcs}"


class TestFQNCollision:
    """Test FQN collision handling across all access control rules.

    Verifies that same-named structs in different modules are correctly distinguished.
    Critical for security: module_a::AdminCap should NOT protect module_b::Pool.
    """

    def test_fqn_collision_module_a_vulnerable(self):
        """Module A withdraw without auth should be flagged."""
        files = _get_fixture_files(
            "_infrastructure/fqn_collision/module_a.move",
            "_infrastructure/fqn_collision/module_b.move",
        )
        result = _run_analysis(files)

        # Both missing-authorization and arbitrary-recipient-drain may flag this
        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("module_a" in fn and "withdraw" in fn and "admin" not in fn for fn in all_funcs), \
            f"Expected module_a::withdraw to be flagged: {all_funcs}"

    def test_fqn_collision_module_b_vulnerable(self):
        """Module B withdraw without auth should be flagged."""
        files = _get_fixture_files(
            "_infrastructure/fqn_collision/module_a.move",
            "_infrastructure/fqn_collision/module_b.move",
        )
        result = _run_analysis(files)

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("module_b" in fn and "withdraw" in fn and "admin" not in fn and "wrong" not in fn
                   for fn in all_funcs), \
            f"Expected module_b::withdraw to be flagged: {all_funcs}"

    def test_fqn_collision_correct_cap_safe(self):
        """Module A withdraw with module A AdminCap should NOT be flagged by auth rules."""
        files = _get_fixture_files(
            "_infrastructure/fqn_collision/module_a.move",
            "_infrastructure/fqn_collision/module_b.move",
        )
        result = _run_analysis(files)

        # Only check auth-related rules (FQN collision is about capability resolution)
        auth_rules = {"missing-authorization"}
        auth_funcs = {v[1] for v in result.violations if v[0] in auth_rules} | \
                     {c[1] for c in result.candidates if c[0] in auth_rules}
        assert not any("module_a" in fn and "withdraw_admin" in fn for fn in auth_funcs), \
            f"module_a::withdraw_admin should NOT be flagged by auth rules: {auth_funcs}"

    def test_fqn_collision_wrong_module_cap_flagged(self):
        """Module B withdraw with module A AdminCap should be flagged.

        Critical security test: Using AdminCap from wrong module should NOT provide protection.
        """
        files = _get_fixture_files(
            "_infrastructure/fqn_collision/module_a.move",
            "_infrastructure/fqn_collision/module_b.move",
        )
        result = _run_analysis(files)

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("withdraw_wrong_cap" in fn for fn in all_funcs), \
            f"Expected withdraw_wrong_cap to be flagged (wrong module AdminCap): {all_funcs}"


class TestUserAssetWriteWithoutOwnership:
    """Test user-asset-write-without-ownership rule.

    Detects writes to user asset containers without verifying caller ownership.
    Rule has :classify clause, so matches go to candidates.
    """

    def test_basic_write_without_ownership_flagged(self):
        """Basic write to user vault without ownership check should be flagged."""
        files = _get_fixture_files("user-asset-write-without-ownership/vulnerable.move")
        result = _run_analysis(files, "user-asset-write-without-ownership")

        # Rule has :classify, check candidates
        func_names = {c[1] for c in result.candidates}
        assert any("steal_modify" in fn for fn in func_names), \
            f"Expected steal_modify to be flagged: {result.candidates}"

    def test_withdraw_without_ownership_flagged(self):
        """Withdraw from vault without ownership check should be flagged."""
        files = _get_fixture_files("user-asset-write-without-ownership/vulnerable.move")
        result = _run_analysis(files, "user-asset-write-without-ownership")

        func_names = {c[1] for c in result.candidates}
        assert any("steal_withdraw" in fn for fn in func_names), \
            f"Expected steal_withdraw to be flagged: {result.candidates}"

    def test_ipa_write_flagged(self):
        """Entry calling helper that writes should be flagged."""
        files = _get_fixture_files("user-asset-write-without-ownership/vulnerable.move")
        result = _run_analysis(files, "user-asset-write-without-ownership")

        func_names = {c[1] for c in result.candidates}
        assert any("modify_via_helper" in fn for fn in func_names), \
            f"Expected modify_via_helper to be flagged: {result.candidates}"

    def test_safe_sender_equality_check(self):
        """Write with sender equality check should NOT be flagged."""
        files = _get_fixture_files("user-asset-write-without-ownership/vulnerable.move")
        result = _run_analysis(files, "user-asset-write-without-ownership")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("safe_modify" in fn for fn in all_funcs), \
            f"safe_modify should NOT be flagged: {all_funcs}"

    def test_safe_transfers_from_sender(self):
        """Deposit from sender should NOT be flagged."""
        files = _get_fixture_files("user-asset-write-without-ownership/vulnerable.move")
        result = _run_analysis(files, "user-asset-write-without-ownership")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("safe_deposit" in fn for fn in all_funcs), \
            f"safe_deposit should NOT be flagged: {all_funcs}"

    def test_safe_with_role(self):
        """Write with role check should NOT be flagged."""
        files = _get_fixture_files("user-asset-write-without-ownership/vulnerable.move")
        result = _run_analysis(files, "user-asset-write-without-ownership")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("admin_modify" in fn for fn in all_funcs), \
            f"admin_modify should NOT be flagged: {all_funcs}"

    def test_ipa_guarded_helper_safe(self):
        """Entry calling guarded helper should NOT be flagged (guard propagates)."""
        files = _get_fixture_files("user-asset-write-without-ownership/vulnerable.move")
        result = _run_analysis(files, "user-asset-write-without-ownership")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("modify_via_guarded_helper" in fn for fn in all_funcs), \
            f"modify_via_guarded_helper should NOT be flagged: {all_funcs}"

    def test_cross_module_write_flagged(self):
        """Cross-module write without ownership check should be flagged."""
        files = _get_fixture_files(
            "user-asset-write-without-ownership/cross_module_entry.move",
            "user-asset-write-without-ownership/cross_module_helper.move",
        )
        result = _run_analysis(files, "user-asset-write-without-ownership")

        func_names = {c[1] for c in result.candidates}
        assert any("modify_cross_module" in fn and "safe" not in fn for fn in func_names), \
            f"Expected modify_cross_module to be flagged: {result.candidates}"

    def test_cross_module_guarded_safe(self):
        """Cross-module with guarded helper should NOT be flagged."""
        files = _get_fixture_files(
            "user-asset-write-without-ownership/cross_module_entry.move",
            "user-asset-write-without-ownership/cross_module_helper.move",
        )
        result = _run_analysis(files, "user-asset-write-without-ownership")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("modify_cross_module_safe" in fn for fn in all_funcs), \
            f"modify_cross_module_safe should NOT be flagged: {all_funcs}"

    def test_fp_owned_object_with_llm_classification(self):
        """Owned object NOT flagged when LLM classifies struct as user asset.

        When LLM classifies a struct as IsUserAsset, functions taking &mut of that
        struct get WritesUserAsset facts. But if the struct is OWNED (not shared),
        Sui runtime already enforces that only the owner can pass &mut.

        Rule uses operates-on-owned-only? filter to skip these.
        """
        files = _get_fixture_files("user-asset-write-without-ownership/vulnerable.move")

        # Inject IsUserAsset fact to simulate LLM classification
        inject_facts = {
            "semantic": [Fact("IsUserAsset", ("test::user_asset_write::OwnedShowcase", True))],
        }
        result = _run_analysis(files, "user-asset-write-without-ownership", inject_facts=inject_facts)

        # Owned object should NOT be flagged - Sui runtime enforces access
        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("add_to_owned_showcase" in fn for fn in all_funcs), \
            f"add_to_owned_showcase should NOT be flagged (owned object): {all_funcs}"

    def test_fp_cross_module_owned_object(self):
        """Cross-module: Function on owned object should NOT be flagged.

        When struct is transferred via transfer::transfer (not share_object),
        it's an owned object. Only owner can pass &mut, so Sui runtime
        enforces access control. No explicit sender check needed.

        This tests positive IsOwnedObject detection for cross-module cases.
        """
        files = _get_fixture_files(
            "user-asset-write-without-ownership/cross_module_owned.move",
            "user-asset-write-without-ownership/cross_module_owned_user.move",
        )

        # Inject IsUserAsset fact to simulate LLM classification
        inject_facts = {
            "semantic": [Fact("IsUserAsset", ("test::owned_showcase_def::Showcase", True))],
        }
        result = _run_analysis(files, "user-asset-write-without-ownership", inject_facts=inject_facts)

        # Owned object should NOT be flagged - Sui runtime enforces access
        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("extract_from_showcase" in fn for fn in all_funcs), \
            f"extract_from_showcase should NOT be flagged (cross-module owned object): {all_funcs}"
        assert not any("add_to_showcase" in fn for fn in all_funcs), \
            f"add_to_showcase should NOT be flagged (cross-module owned object): {all_funcs}"


class TestGenericTypeMismatch:
    """Test generic-type-mismatch rule.

    Detects generic type parameters without type_name::get validation.
    """

    def test_withdraw_without_validation(self):
        """Function with generic type parameter without validation should be flagged."""
        files = _get_fixture_files("generic-type-mismatch/vulnerable.move")
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("withdraw" in fn and "validation" not in fn and "role" not in fn for fn in all_funcs), \
            f"Expected withdraw to be flagged: {all_funcs}"

    def test_withdraw_via_helper_flagged(self):
        """Entry calling helper with generic type should be flagged."""
        files = _get_fixture_files("generic-type-mismatch/vulnerable.move")
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("withdraw_via_helper" in fn for fn in all_funcs), \
            f"Expected withdraw_via_helper to be flagged: {all_funcs}"

    def test_with_validation_safe(self):
        """Function with type_name::get validation should NOT be flagged."""
        files = _get_fixture_files("generic-type-mismatch/vulnerable.move")
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("withdraw_with_validation" in fn for fn in all_funcs), \
            f"withdraw_with_validation should NOT be flagged: {all_funcs}"

    def test_with_role_safe(self):
        """Function with role check should NOT be flagged."""
        files = _get_fixture_files("generic-type-mismatch/vulnerable.move")
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("withdraw_with_role" in fn for fn in all_funcs), \
            f"withdraw_with_role should NOT be flagged: {all_funcs}"

    def test_no_extraction_safe(self):
        """Function without value extraction should NOT be flagged."""
        files = _get_fixture_files("generic-type-mismatch/vulnerable.move")
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("get_balance" in fn for fn in all_funcs), \
            f"get_balance should NOT be flagged: {all_funcs}"

    def test_cross_module_unvalidated_flagged(self):
        """Cross-module: Entry calling unvalidated helper should be flagged."""
        files = _get_fixture_files(
            "generic-type-mismatch/cross_module_a.move",
            "generic-type-mismatch/cross_module_b.move",
        )
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("withdraw_cross_module" in fn and "safe" not in fn for fn in all_funcs), \
            f"Expected withdraw_cross_module to be flagged: {all_funcs}"

    def test_cross_module_validated_safe(self):
        """Cross-module: Entry calling validated helper should NOT be flagged.

        Fixed: ValidatesGenericType now propagates through call graph (IPA).
        When a function calls a validating callee, the caller is marked as safe.
        """
        files = _get_fixture_files(
            "generic-type-mismatch/cross_module_a.move",
            "generic-type-mismatch/cross_module_b.move",
        )
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # withdraw_cross_module_safe calls validated helper, should NOT be flagged
        assert not any("withdraw_cross_module_safe" in fn for fn in all_funcs), \
            f"withdraw_cross_module_safe should NOT be flagged (calls validated helper): {all_funcs}"

    def test_fqn_conflict_only_vulnerable_flagged(self):
        """FQN conflict: Only fqn_col_b::withdraw (no validation) should be flagged."""
        files = _get_fixture_files(
            "generic-type-mismatch/fqn_collision_a.move",
            "generic-type-mismatch/fqn_collision_b.move",
        )
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("fqn_col_b" in fn and "withdraw" in fn for fn in all_funcs), \
            f"Expected fqn_col_b::withdraw to be flagged: {all_funcs}"

    def test_fqn_conflict_safe_not_flagged(self):
        """FQN conflict: module_a::withdraw (has validation) should NOT be flagged."""
        files = _get_fixture_files(
            "generic-type-mismatch/fqn_collision_a.move",
            "generic-type-mismatch/fqn_collision_b.move",
        )
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("module_a" in fn and "withdraw" in fn for fn in all_funcs), \
            f"module_a::withdraw should NOT be flagged: {all_funcs}"

    def test_ipa_fqn_collision_validated_safe(self):
        """IPA FQN collision: Calling validated helper (module_a::validate) should be safe.

        Tests that IPA propagation uses exact FQN matching, not simple name matching.
        module_a::validate validates, module_b::validate does not.
        module_c calls module_a::validate and should be marked safe.
        """
        files = _get_fixture_files(
            "generic-type-mismatch/ipa_fqn_a.move",
            "generic-type-mismatch/ipa_fqn_b.move",
            "generic-type-mismatch/ipa_fqn_c.move",
            "generic-type-mismatch/ipa_fqn_d.move",
        )
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # module_c::withdraw_calls_validated calls module_a::validate (validates) -> should be safe
        assert not any("withdraw_calls_validated" in fn for fn in all_funcs), \
            f"withdraw_calls_validated should NOT be flagged (calls validating helper): {all_funcs}"

    def test_ipa_fqn_collision_unvalidated_flagged(self):
        """IPA FQN collision: Calling unvalidated helper (module_b::validate) should be flagged.

        Tests that IPA propagation uses exact FQN matching, not simple name matching.
        module_b::validate does NOT validate, so callers should be flagged.
        """
        files = _get_fixture_files(
            "generic-type-mismatch/ipa_fqn_a.move",
            "generic-type-mismatch/ipa_fqn_b.move",
            "generic-type-mismatch/ipa_fqn_c.move",
            "generic-type-mismatch/ipa_fqn_d.move",
        )
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # module_d::withdraw_calls_unvalidated calls module_b::validate (does NOT validate) -> flagged
        assert any("withdraw_calls_unvalidated" in fn for fn in all_funcs), \
            f"withdraw_calls_unvalidated should be flagged: {all_funcs}"

    def test_multihop_abc_validated_safe(self):
        """Multi-hop A->B->C: Validation propagates through 3-module chain.

        module_a calls module_b::validate_via_c which calls module_c::validate.
        The validation in C should propagate to B then to A.
        """
        files = _get_fixture_files(
            "generic-type-mismatch/multihop_a.move",
            "generic-type-mismatch/multihop_b.move",
            "generic-type-mismatch/multihop_c.move",
        )
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # withdraw_multihop_safe calls B which calls C which validates -> should be SAFE
        assert not any("withdraw_multihop_safe" in fn for fn in all_funcs), \
            f"withdraw_multihop_safe should NOT be flagged (3-hop validation chain): {all_funcs}"

    def test_multihop_abc_unvalidated_flagged(self):
        """Multi-hop A->B->C: No validation in chain means vulnerable.

        module_a calls module_b::no_validate which does NOT call module_c::validate.
        """
        files = _get_fixture_files(
            "generic-type-mismatch/multihop_a.move",
            "generic-type-mismatch/multihop_b.move",
            "generic-type-mismatch/multihop_c.move",
        )
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # withdraw_multihop_unsafe calls B::no_validate (no validation) -> FLAGGED
        assert any("withdraw_multihop_unsafe" in fn for fn in all_funcs), \
            f"withdraw_multihop_unsafe should be flagged (no validation in chain): {all_funcs}"

    def test_multihop_no_call_flagged(self):
        """Multi-hop: No helper call at all means vulnerable."""
        files = _get_fixture_files(
            "generic-type-mismatch/multihop_a.move",
            "generic-type-mismatch/multihop_b.move",
            "generic-type-mismatch/multihop_c.move",
        )
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # withdraw_no_call has no validation at all -> FLAGGED
        assert any("withdraw_no_call" in fn for fn in all_funcs), \
            f"withdraw_no_call should be flagged (no validation): {all_funcs}"

    def test_validation_helper_without_type_check(self):
        """Entry point with validation helper that doesn't type-check should be flagged.

        Pattern: withdraw<T> calls validate_withdraw<T> then coin::take<T>.
        validate_withdraw doesn't call type_name::get<T>, so withdraw is vulnerable.
        Only the entry point is flagged - validation helper is mentioned in context.
        Based on Navi Protocol lending_core pattern.
        """
        files = _get_fixture_files("generic-type-mismatch/validation_helper.move")
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # withdraw (entry point) should be flagged - it has extraction without validation
        assert any("withdraw" in fn and "safe" not in fn for fn in all_funcs), \
            f"Expected withdraw to be flagged (entry point with unvalidated extraction): {all_funcs}"

    def test_validation_helper_with_type_check_safe(self):
        """Entry point with validating helper should NOT be flagged.

        withdraw_safe calls validate_withdraw_safe which has type_name::get<CoinType>.
        The validation propagates to caller via IPA, so withdraw_safe is safe.
        """
        files = _get_fixture_files("generic-type-mismatch/validation_helper.move")
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # withdraw_safe should NOT be flagged - its helper validates the type
        assert not any("withdraw_safe" in fn for fn in all_funcs), \
            f"withdraw_safe should NOT be flagged (helper validates): {all_funcs}"

    def test_caller_validates_before_calling_extraction_safe(self):
        """Entry point that validates BEFORE calling internal extraction function is safe.

        withdraw_caller_validates calls type_name::get<CoinType> first, then calls
        execute_withdraw which has extraction but no validation. Should be safe.
        """
        files = _get_fixture_files("generic-type-mismatch/validation_helper.move")
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # withdraw_caller_validates should NOT be flagged - it validates before calling extraction
        assert not any("withdraw_caller_validates" in fn for fn in all_funcs), \
            f"withdraw_caller_validates should NOT be flagged (validates before extraction): {all_funcs}"

    def test_validation_helper_with_caller_extraction_flagged(self):
        """Validation helper whose callers do extraction should be flagged.

        Pattern: validate_withdraw<T> is called from execute_withdraw<T> which has coin::take<T>.
        validate_withdraw has TypeReachesExtractionInCallers but no TypeValidated.
        This reproduces Navi Protocol OS-NVI-ADV-00 finding.
        """
        files = _get_fixture_files("generic-type-mismatch/validation_helper.move")
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # validate_withdraw should be flagged - it has validation responsibility but no type check
        assert any(fn.endswith("validate_withdraw") for fn in all_funcs), \
            f"Expected validate_withdraw to be flagged (has caller extraction, no validation): {all_funcs}"

    def test_type_name_get_for_logging_flagged(self):
        """type_name::get used for logging/events should NOT count as validation.

        withdraw_with_logging uses type_name::get<T>() in emit() - this is NOT validation.
        The function should be flagged because it has extraction without actual type validation.
        """
        files = _get_fixture_files("generic-type-mismatch/logging_not_validation.move")
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # Function that only logs type should be flagged
        assert any("withdraw_with_logging" in fn for fn in all_funcs), \
            f"Expected withdraw_with_logging to be flagged (logging is not validation): {all_funcs}"

    def test_type_name_get_discarded_flagged(self):
        """type_name::get with discarded result should NOT count as validation.

        withdraw_discarded_result assigns type_name::get<T>() to _type_check but never uses it.
        The function should be flagged because there's no actual validation.
        """
        files = _get_fixture_files("generic-type-mismatch/logging_not_validation.move")
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # Function that discards type_name::get result should be flagged
        assert any("withdraw_discarded_result" in fn for fn in all_funcs), \
            f"Expected withdraw_discarded_result to be flagged (discarded result): {all_funcs}"

    def test_type_name_get_in_assert_safe(self):
        """type_name::get used in assert! should count as validation.

        withdraw_with_assert uses type_name::get<T>() in an assert! comparison.
        This IS actual validation and should NOT be flagged.
        """
        files = _get_fixture_files("generic-type-mismatch/logging_not_validation.move")
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # Function that asserts on type should NOT be flagged
        assert not any("withdraw_with_assert" in fn for fn in all_funcs), \
            f"withdraw_with_assert should NOT be flagged (validates in assert): {all_funcs}"

    def test_type_name_get_stored_then_asserted_safe(self):
        """type_name::get stored then used in assert! should count as validation.

        withdraw_with_stored_assert stores the result then uses it in assert!.
        This IS actual validation and should NOT be flagged.
        """
        files = _get_fixture_files("generic-type-mismatch/logging_not_validation.move")
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # Function that stores then asserts should NOT be flagged
        assert not any("withdraw_with_stored_assert" in fn for fn in all_funcs), \
            f"withdraw_with_stored_assert should NOT be flagged (stored then asserted): {all_funcs}"

    def test_with_defining_ids_validation(self):
        """type_name::with_defining_ids<T>() in assertion counts as validation."""
        files = _get_fixture_files("generic-type-mismatch/with_defining_ids.move")
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # withdraw_with_defining_ids validates with with_defining_ids, should NOT be flagged
        assert not any("withdraw_with_defining_ids" in fn for fn in all_funcs), \
            f"withdraw_with_defining_ids should NOT be flagged (validates with with_defining_ids): {all_funcs}"
        # withdraw_no_validation has no validation, SHOULD be flagged
        assert any("withdraw_no_validation" in fn for fn in all_funcs), \
            f"withdraw_no_validation should be flagged: {all_funcs}"

    def test_readonly_lookup_not_flagged(self):
        """Read-only lookup functions (no &mut params) should NOT be flagged.

        is_allowed<T> is called from withdraw_checked<T> which does extraction.
        IPA propagates TypeReachesExtractionInCallers to is_allowed.
        But is_allowed has no &mut params - it's read-only and can't extract.
        """
        files = _get_fixture_files("generic-type-mismatch/readonly_lookup.move")
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # is_allowed is read-only (no &mut), should NOT be flagged even with IPA
        assert not any("is_allowed" in fn and "withdraw" not in fn for fn in all_funcs), \
            f"is_allowed should NOT be flagged (read-only lookup): {all_funcs}"
        # withdraw and withdraw_checked have &mut params, SHOULD be flagged
        assert any("withdraw" in fn for fn in all_funcs), \
            f"withdraw should be flagged (has &mut, no validation): {all_funcs}"

    def test_validation_helper_ipa_propagation(self):
        """Validation via helper function should propagate through IPA.

        type_to_string<T>() calls type_name::get<T>() - it's a pure validator.
        withdraw_with_helper<T>() calls type_to_string<T>() then extracts.
        Should NOT be flagged - inherits validation via IPA.
        """
        files = _get_fixture_files("generic-type-mismatch/validation_helper_ipa.move")
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # withdraw_with_helper calls validator helper, should NOT be flagged
        assert not any("withdraw_with_helper" in fn for fn in all_funcs), \
            f"withdraw_with_helper should NOT be flagged (validated via helper IPA): {all_funcs}"
        # withdraw_no_validation has no validation, SHOULD be flagged
        assert any("withdraw_no_validation" in fn for fn in all_funcs), \
            f"withdraw_no_validation should be flagged: {all_funcs}"

    def test_cross_file_phantom_binding(self):
        """Phantom type binding should work across files/modules.

        Pool<phantom L> is defined in pool_module (separate file), used in interface_module.
        L should be recognized as phantom-bound even when Pool is imported.
        """
        files = _get_fixture_files(
            "generic-type-mismatch/cross_file_phantom_pool.move",
            "generic-type-mismatch/cross_file_phantom_interface.move"
        )
        result = _run_analysis(files, "generic-type-mismatch")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # withdraw_with_phantom: L is phantom-bound, C1 is validated - should NOT be flagged
        assert not any("withdraw_with_phantom" in fn for fn in all_funcs), \
            f"withdraw_with_phantom should NOT be flagged (L phantom-bound, C1 validated): {all_funcs}"
        # withdraw_no_c1_validation: L is phantom-bound but C1 is NOT - SHOULD be flagged
        assert any("withdraw_no_c1_validation" in fn for fn in all_funcs), \
            f"withdraw_no_c1_validation should be flagged (C1 not validated): {all_funcs}"


class TestSharedCapabilityExposure:
    """Test shared-capability-exposure rule.

    Detects admin capabilities shared instead of transferred.
    """

    # Mock LLM responses: these structs would be classified as roles by LLM
    MOCK_ROLE_FACTS = {
        "file": [
            Fact("IsCapability", ("test::shared_capability_exposure::SharedAdminCap",)),
            Fact("IsCapability", ("test::shared_capability_exposure::SharedOwnerCap",)),
            # ProperAdminCap gets IsCapability from structural analysis (transferred to sender)
            # Pool is NOT a role (has Balance field, not single-UID capability)
        ]
    }

    def test_shared_admin_cap_flagged(self):
        """SharedAdminCap should be flagged."""
        files = _get_fixture_files("shared-capability-exposure/vulnerable.move")
        result = _run_analysis(files, "shared-capability-exposure", inject_facts=self.MOCK_ROLE_FACTS)

        all_roles = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("SharedAdminCap" in r for r in all_roles), \
            f"Expected SharedAdminCap to be flagged: {all_roles}"

    def test_shared_owner_cap_flagged(self):
        """SharedOwnerCap should be flagged."""
        files = _get_fixture_files("shared-capability-exposure/vulnerable.move")
        result = _run_analysis(files, "shared-capability-exposure", inject_facts=self.MOCK_ROLE_FACTS)

        all_roles = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("SharedOwnerCap" in r for r in all_roles), \
            f"Expected SharedOwnerCap to be flagged: {all_roles}"

    def test_proper_admin_cap_safe(self):
        """ProperAdminCap should NOT be flagged (transferred, not shared)."""
        files = _get_fixture_files("shared-capability-exposure/vulnerable.move")
        result = _run_analysis(files, "shared-capability-exposure", inject_facts=self.MOCK_ROLE_FACTS)

        all_roles = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("ProperAdminCap" in r for r in all_roles), \
            f"ProperAdminCap should NOT be flagged: {all_roles}"

    def test_pool_not_flagged(self):
        """Pool struct should NOT be flagged (not a role)."""
        files = _get_fixture_files("shared-capability-exposure/vulnerable.move")
        result = _run_analysis(files, "shared-capability-exposure", inject_facts=self.MOCK_ROLE_FACTS)

        all_roles = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("Pool" in r for r in all_roles), \
            f"Pool should NOT be flagged: {all_roles}"

    def test_cross_module_shared_cap_flagged(self):
        """Cross-module: Cap defined in one module, shared in another should be flagged.

        Fixed: IsSharedObject detection now tracks cross-module patterns.
        Pattern: let cap = module::create_cap(); share_object(cap)
        Uses FunReturnType facts to track the struct type through function calls.
        """
        # Mock: LLM would classify AdminCap as a role
        mock_facts = {
            "file": [Fact("IsCapability", ("test::cap_module::AdminCap",))]
        }
        files = _get_fixture_files(
            "shared-capability-exposure/cross_module_cap.move",
            "shared-capability-exposure/cross_module_init.move",
        )
        result = _run_analysis(files, "shared-capability-exposure", inject_facts=mock_facts)

        all_roles = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # AdminCap should be flagged (shared via cross-module call)
        assert any("AdminCap" in r for r in all_roles), \
            f"AdminCap should be flagged (shared via cross-module call): {all_roles}"

    def test_fqn_conflict_only_shared_flagged(self):
        """FQN conflict: Only module_a::AdminCap (shared) should be flagged."""
        # Mock: Both AdminCaps would be classified as roles by LLM
        mock_facts = {
            "file": [
                Fact("IsCapability", ("test::module_a::AdminCap",)),
                Fact("IsCapability", ("test::module_b::AdminCap",)),
            ]
        }
        files = _get_fixture_files(
            "shared-capability-exposure/fqn_collision_a.move",
            "shared-capability-exposure/fqn_collision_b.move",
        )
        result = _run_analysis(files, "shared-capability-exposure", inject_facts=mock_facts)

        all_roles = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("module_a" in r and "AdminCap" in r for r in all_roles), \
            f"Expected module_a::AdminCap to be flagged: {all_roles}"

    def test_fqn_conflict_transferred_safe(self):
        """FQN conflict: module_b::AdminCap (transferred) should NOT be flagged."""
        # Mock: Both AdminCaps would be classified as roles by LLM
        mock_facts = {
            "file": [
                Fact("IsCapability", ("test::module_a::AdminCap",)),
                Fact("IsCapability", ("test::module_b::AdminCap",)),
            ]
        }
        files = _get_fixture_files(
            "shared-capability-exposure/fqn_collision_a.move",
            "shared-capability-exposure/fqn_collision_b.move",
        )
        result = _run_analysis(files, "shared-capability-exposure", inject_facts=mock_facts)

        all_roles = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("module_b" in r and "AdminCap" in r for r in all_roles), \
            f"module_b::AdminCap should NOT be flagged: {all_roles}"


class TestTestOnlyMissing:
    """Test test-only-missing rule.

    Detects public functions returning privileged capabilities without #[test_only].
    """

    def test_create_admin_cap_for_testing_flagged(self):
        """create_admin_cap_for_testing should be flagged."""
        files = _get_fixture_files("test-only-missing/vulnerable.move")
        result = _run_analysis(files, "test-only-missing")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("create_admin_cap_for_testing" in fn for fn in all_funcs), \
            f"Expected create_admin_cap_for_testing to be flagged: {all_funcs}"

    def test_vulnerable_functions_flagged(self):
        """Should flag both create_admin_cap_for_testing and create_cap_via_helper."""
        files = _get_fixture_files("test-only-missing/vulnerable.move")
        result = _run_analysis(files, "test-only-missing")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        # Should flag both functions that return AdminCap without #[test_only]
        # get_admin_cap_unsafe doesn't return a value, so not caught by this rule
        assert len(all_funcs) == 2, \
            f"Expected exactly 2 violations, got {len(all_funcs)}: {all_funcs}"
        assert any("create_admin_cap_for_testing" in fn for fn in all_funcs), \
            f"Expected create_admin_cap_for_testing to be flagged: {all_funcs}"
        assert any("create_cap_via_helper" in fn for fn in all_funcs), \
            f"Expected create_cap_via_helper to be flagged: {all_funcs}"

    def test_init_safe(self):
        """init() should NOT be flagged."""
        files = _get_fixture_files("test-only-missing/vulnerable.move")
        result = _run_analysis(files, "test-only-missing")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("::init" in fn for fn in all_funcs), \
            f"init should NOT be flagged: {all_funcs}"

    def test_with_role_check_safe(self):
        """create_operator_cap (has role check) should NOT be flagged."""
        files = _get_fixture_files("test-only-missing/vulnerable.move")
        result = _run_analysis(files, "test-only-missing")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("create_operator_cap" in fn for fn in all_funcs), \
            f"create_operator_cap should NOT be flagged: {all_funcs}"

    def test_withdraw_not_flagged(self):
        """withdraw (doesn't return cap) should NOT be flagged."""
        files = _get_fixture_files("test-only-missing/vulnerable.move")
        result = _run_analysis(files, "test-only-missing")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("withdraw" in fn and "withdraw" == fn.split("::")[-1] for fn in all_funcs), \
            f"withdraw should NOT be flagged: {all_funcs}"

    def test_ipa_returns_cap_via_helper_flagged(self):
        """IPA: Public function returning cap via helper should be flagged."""
        files = _get_fixture_files("test-only-missing/vulnerable.move")
        result = _run_analysis(files, "test-only-missing")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("create_cap_via_helper" in fn for fn in all_funcs), \
            f"Expected create_cap_via_helper to be flagged: {all_funcs}"

    def test_cross_module_returns_cap_flagged(self):
        """Cross-module: wrapper returning cap from another module should be flagged."""
        # Mock: AdminCap is privileged
        mock_facts = {
            "file": [Fact("IsPrivileged", ("test::cap_module::AdminCap",))]
        }
        files = _get_fixture_files(
            "test-only-missing/cross_module_cap.move",
            "test-only-missing/cross_module_wrapper.move",
        )
        result = _run_analysis(files, "test-only-missing", inject_facts=mock_facts)

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("get_admin_cap" in fn for fn in all_funcs), \
            f"Expected get_admin_cap to be flagged: {all_funcs}"

    def test_fqn_conflict_no_test_only_flagged(self):
        """FQN conflict: module_a::create_admin_cap (no test_only) should be flagged."""
        # Mock: Both AdminCaps are privileged
        mock_facts = {
            "file": [
                Fact("IsPrivileged", ("test::module_a::AdminCap",)),
                Fact("IsPrivileged", ("test::module_b::AdminCap",)),
            ]
        }
        files = _get_fixture_files(
            "test-only-missing/fqn_collision_a.move",
            "test-only-missing/fqn_collision_b.move",
        )
        result = _run_analysis(files, "test-only-missing", inject_facts=mock_facts)

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("module_a" in fn and "create_admin_cap" in fn for fn in all_funcs), \
            f"Expected module_a::create_admin_cap to be flagged: {all_funcs}"

    def test_fqn_conflict_with_test_only_safe(self):
        """FQN conflict: module_b::create_admin_cap (has test_only) should NOT be flagged."""
        # Mock: Both AdminCaps are privileged
        mock_facts = {
            "file": [
                Fact("IsPrivileged", ("test::module_a::AdminCap",)),
                Fact("IsPrivileged", ("test::module_b::AdminCap",)),
            ]
        }
        files = _get_fixture_files(
            "test-only-missing/fqn_collision_a.move",
            "test-only-missing/fqn_collision_b.move",
        )
        result = _run_analysis(files, "test-only-missing", inject_facts=mock_facts)

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("module_b" in fn and "create_admin_cap" in fn for fn in all_funcs), \
            f"module_b::create_admin_cap should NOT be flagged: {all_funcs}"


class TestCreationSitePerStruct:
    """Test per-struct creation site tracking.

    Bug: When init() creates multiple structs with different transfer patterns
    (one transferred, one shared), detect_transfer_patterns() incorrectly
    merges patterns at the function level instead of tracking per-struct.

    Example from real project:
    - PrizePoolCap: transferred to sender → should be privileged
    - PrizePool: shared → should NOT be privileged

    Bug behavior: Both get marked with "transferred to sender → shared"
    because the function has both transfer() and share_object() calls.
    """

    def test_creation_site_per_struct_tracking(self):
        """Each struct should have its own transfer pattern, not function-level merge.

        This test verifies the CreationSite data directly, not through rules.
        """
        from analysis.patterns import collect_creation_sites

        files = _get_fixture_files("_infrastructure/creation_site_per_struct/prize_pool.move")
        ctx = ProjectContext(files)
        run_structural_analysis(ctx)

        creation_sites = collect_creation_sites(ctx)

        # Find creation sites for both structs
        cap_sites = creation_sites.get("test::prize_pool::PrizePoolCap", [])
        pool_sites = creation_sites.get("test::prize_pool::PrizePool", [])

        assert len(cap_sites) > 0, "PrizePoolCap should have creation sites"
        assert len(pool_sites) > 0, "PrizePool should have creation sites"

        cap_site = cap_sites[0]
        pool_site = pool_sites[0]

        # BUG: Currently both get shared=True because function has share_object call
        # EXPECTED: Only pool should be shared, cap should NOT be shared
        assert not cap_site.shared, \
            f"PrizePoolCap should NOT be marked as shared (it's transferred to sender): {cap_site}"
        assert cap_site.transferred_to == "sender", \
            f"PrizePoolCap should be transferred to sender: {cap_site}"

        # Pool should be shared
        assert pool_site.shared, \
            f"PrizePool should be marked as shared: {pool_site}"

    def test_cap_is_privileged_not_shared(self):
        """PrizePoolCap should be classified as privileged (transferred to sender).

        When creation site tracking is correct, LLM prompt will show:
        - PrizePoolCap: "transferred to sender" (NO "shared")
        - PrizePool: "shared"

        This affects LLM classification: privileged structs are those
        transferred to sender in init, not shared.
        """
        files = _get_fixture_files("_infrastructure/creation_site_per_struct/prize_pool.move")
        ctx = ProjectContext(files)
        run_structural_analysis(ctx)
        run_fact_propagation(ctx)

        # Check IsSharedObject facts
        shared_structs = set()
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "IsSharedObject":
                    shared_structs.add(fact.args[0])

        # PrizePool should be shared
        assert "test::prize_pool::PrizePool" in shared_structs, \
            f"PrizePool should have IsSharedObject fact: {shared_structs}"

        # PrizePoolCap should NOT be shared
        assert "test::prize_pool::PrizePoolCap" not in shared_structs, \
            f"PrizePoolCap should NOT have IsSharedObject fact: {shared_structs}"


class TestSenderParamTracking:
    """Test interprocedural sender tracking through function parameters.

    Issue: When init() passes sender value to a helper function that creates
    and transfers a struct, the struct should be classified as "transferred to sender"
    not "transferred to param".
    """

    def test_sender_param_basic(self):
        """Struct created in helper receiving sender param should be transferred to sender."""
        from analysis.patterns import collect_creation_sites

        files = _get_fixture_files("_infrastructure/sender_param_tracking/sender_param.move")
        ctx = ProjectContext(files)
        run_structural_analysis(ctx)
        run_fact_propagation(ctx)

        creation_sites = collect_creation_sites(ctx)

        # Check Cap (created in create_and_transfer, called from init with sender)
        cap_sites = creation_sites.get("test::sender_param::Cap", [])
        assert len(cap_sites) > 0, "Cap should have creation sites"

        cap_site = cap_sites[0]
        assert cap_site.func_name == "test::sender_param::create_and_transfer", \
            f"Cap should be created in create_and_transfer: {cap_site.func_name}"
        assert cap_site.transferred_to == "sender", \
            f"Cap should be transferred to sender (not param): {cap_site.transferred_to}"

        # Check HelperCap (created in helper_create, called with sender from create_helper_cap)
        helper_cap_sites = creation_sites.get("test::sender_param::HelperCap", [])
        assert len(helper_cap_sites) > 0, "HelperCap should have creation sites"

        helper_cap_site = helper_cap_sites[0]
        assert helper_cap_site.func_name == "test::sender_param::helper_create", \
            f"HelperCap should be created in helper_create: {helper_cap_site.func_name}"
        assert helper_cap_site.transferred_to == "sender", \
            f"HelperCap should be transferred to sender (not param): {helper_cap_site.transferred_to}"

    def test_sender_derived_param_facts_generated(self):
        """SenderDerivedParam facts should be generated for functions receiving sender values."""
        files = _get_fixture_files("_infrastructure/sender_param_tracking/sender_param.move")
        ctx = ProjectContext(files)
        run_structural_analysis(ctx)
        run_fact_propagation(ctx)

        sender_derived_params = {}
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "SenderDerivedParam":
                    func_name, param_idx = fact.args
                    sender_derived_params.setdefault(func_name, set()).add(param_idx)

        # create_and_transfer should have param 0 (recipient) marked as sender-derived
        assert "test::sender_param::create_and_transfer" in sender_derived_params, \
            "create_and_transfer should have SenderDerivedParam facts"
        assert 0 in sender_derived_params["test::sender_param::create_and_transfer"], \
            f"create_and_transfer param 0 should be sender-derived: {sender_derived_params}"

        # helper_create should have param 0 (recipient) marked as sender-derived
        assert "test::sender_param::helper_create" in sender_derived_params, \
            "helper_create should have SenderDerivedParam facts"
        assert 0 in sender_derived_params["test::sender_param::helper_create"], \
            f"helper_create param 0 should be sender-derived: {sender_derived_params}"

    def test_iterator_cap_sender_param(self):
        """IteratorCap created in public func receiving sender from init should be sender-transferred.

        Regression test for the exact case:
        - init() calls ctx.sender() and stores in `authority`
        - init() calls create_iterator_cap(&cap, authority, ctx)
        - create_iterator_cap() receives `recipient` param (which IS sender)
        - create_iterator_cap() transfers IteratorCap to `recipient`
        - Should be classified as "transferred to sender", NOT "transferred to param"
        """
        from analysis.patterns import collect_creation_sites

        files = _get_fixture_files("_infrastructure/sender_param_tracking/iterator_cap.move")
        ctx = ProjectContext(files)
        run_structural_analysis(ctx)
        run_fact_propagation(ctx)

        # Debug: print SenderDerivedParam facts
        sender_derived_params = {}
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "SenderDerivedParam":
                    func_name, param_idx = fact.args
                    sender_derived_params.setdefault(func_name, set()).add(param_idx)

        # create_iterator_cap should have param 1 (recipient) marked as sender-derived
        # (param 0 is _self: &IteratorCreatorCap, param 1 is recipient: address)
        assert "test::iterator::create_iterator_cap" in sender_derived_params, \
            f"create_iterator_cap should have SenderDerivedParam facts: {sender_derived_params}"
        assert 1 in sender_derived_params["test::iterator::create_iterator_cap"], \
            f"create_iterator_cap param 1 (recipient) should be sender-derived: {sender_derived_params}"

        creation_sites = collect_creation_sites(ctx)

        # IteratorCap should be transferred to sender (not param!)
        iter_cap_sites = creation_sites.get("test::iterator::IteratorCap", [])
        assert len(iter_cap_sites) > 0, f"IteratorCap should have creation sites: {creation_sites.keys()}"

        iter_cap_site = iter_cap_sites[0]
        assert iter_cap_site.func_name == "test::iterator::create_iterator_cap", \
            f"IteratorCap should be created in create_iterator_cap: {iter_cap_site.func_name}"
        assert iter_cap_site.transferred_to == "sender", \
            f"IteratorCap should be transferred to sender (not param): {iter_cap_site.transferred_to}"


class TestMutableConfigSetter:
    """Test missing-mutable-config-setter rule detection.

    This rule ensures mutable config fields have privileged setter functions.
    A field is flagged if:
    1. It's classified as IsMutableConfigField (LLM-determined)
    2. It has NO HasPrivilegedSetter fact (no non-init function that writes it with role/sender check)

    NOTE: These tests are xfail because the (struct ?struct field ?field) pattern
    is not yet implemented in the rule engine. The rule engine only supports
    fun/role/event/const patterns. Implementing struct-field iteration requires
    changes to src/rules/hy/macros.hy and src/rules/utils.py.
    """

    def test_no_setter_flagged(self):
        """Config field with no setter should be flagged."""
        # Mock: Pool.fee_rate is mutable config, AdminCap is privileged
        mock_facts = {
            "file": [
                Fact("FieldClassification", ("test::pool::Pool", "fee_rate", "mutable_config", False, 1.0, "")),
                Fact("IsPrivileged", ("test::pool::AdminCap",)),
            ]
        }
        files = _get_fixture_files("missing-mutable-config-setter/no_setter.move")
        result = _run_analysis(files, "missing-mutable-config-setter", inject_facts=mock_facts)

        # Should flag Pool.fee_rate as missing setter
        # v[1] is a tuple (struct, field) for mutable-config-field pattern
        violations = {v[1] for v in result.violations}
        assert ("test::pool::Pool", "fee_rate") in violations, \
            f"Pool.fee_rate should be flagged as missing setter: {result.violations}"

    def test_privileged_setter_not_flagged(self):
        """Config field with privileged setter should NOT be flagged."""
        # Mock: Pool.fee_rate is mutable config, AdminCap is privileged
        mock_facts = {
            "file": [
                Fact("FieldClassification", ("test::pool::Pool", "fee_rate", "mutable_config", False, 1.0, "")),
                Fact("IsPrivileged", ("test::pool::AdminCap",)),
            ]
        }
        files = _get_fixture_files("missing-mutable-config-setter/with_privileged_setter.move")
        result = _run_analysis(files, "missing-mutable-config-setter", inject_facts=mock_facts)

        # Should NOT flag Pool.fee_rate (has set_fee_rate with AdminCap)
        # v[1] is a tuple (struct, field) for mutable-config-field pattern
        violations = {v[1] for v in result.violations}
        assert ("test::pool::Pool", "fee_rate") not in violations, \
            f"Pool.fee_rate should NOT be flagged (has privileged setter): {result.violations}"

    def test_immutable_config_not_flagged(self):
        """Immutable config field should NOT be flagged."""
        # Mock: Token.decimals is NOT mutable (immutable config), AdminCap is privileged
        # NOTE: We don't inject IsMutableConfigField for decimals
        mock_facts = {
            "file": [
                Fact("IsPrivileged", ("test::token::AdminCap",)),
            ]
        }
        files = _get_fixture_files("missing-mutable-config-setter/immutable_config.move")
        result = _run_analysis(files, "missing-mutable-config-setter", inject_facts=mock_facts)

        # Should NOT flag Token.decimals (not mutable config)
        # v[1] is a tuple (struct, field) for mutable-config-field pattern
        violations = {v[1] for v in result.violations}
        assert ("test::token::Token", "decimals") not in violations, \
            f"Token.decimals should NOT be flagged (immutable config): {result.violations}"

    def test_same_struct_name_different_modules(self):
        """Same struct name in different modules tracked separately by FQN."""
        mock_facts = {
            "file": [
                # Both modules have Pool.fee_rate as mutable config
                Fact("FieldClassification", ("test::dex_a::Pool", "fee_rate", "mutable_config", False, 1.0, "")),
                Fact("FieldClassification", ("test::lending_b::Pool", "fee_rate", "mutable_config", False, 1.0, "")),
            ]
        }
        files = _get_fixture_files(
            "missing-mutable-config-setter/fqn_collision_a.move",
            "missing-mutable-config-setter/fqn_collision_b.move"
        )
        result = _run_analysis(files, "missing-mutable-config-setter", inject_facts=mock_facts)

        # v[1] is tuple (struct, field) for mutable-config-field pattern
        violations = {v[1] for v in result.violations}

        # test::dex_a::Pool should NOT be flagged (has set_fee with sender check)
        assert ("test::dex_a::Pool", "fee_rate") not in violations, \
            "test::dex_a::Pool.fee_rate should NOT be flagged (has privileged setter with sender check)"

        # test::lending_b::Pool SHOULD be flagged (no setter)
        assert ("test::lending_b::Pool", "fee_rate") in violations, \
            "test::lending_b::Pool.fee_rate should be flagged (no setter)"


# =============================================================================
# sensitive-internal-public-exposure
# =============================================================================


class TestSensitiveInternalPublicExposure:
    """Test sensitive-internal-public-exposure rule.

    Detects internal helper functions that:
    1. ARE called internally (have callers within the package)
    2. Handle sensitive operations (balance mutations, state updates)
    3. But have `public` visibility instead of `public(friend)` or `public(package)`

    Has :classify, so matches go to candidates (LLM needed for final decision).
    """

    def test_vulnerable_internal_helper_with_caller(self):
        """Public helper called internally without auth should be flagged."""
        files = _get_fixture_files("sensitive-internal-public-exposure/vulnerable.move")
        result = _run_analysis(files, "sensitive-internal-public-exposure")

        # Should be candidate (has :classify)
        candidates = {c[1] for c in result.candidates}
        assert any("do_withdraw" in c for c in candidates), \
            f"do_withdraw should be flagged as candidate: {result.candidates}"

    def test_vulnerable_state_mutation_helper(self):
        """Public state mutation helper called internally should be flagged."""
        files = _get_fixture_files("sensitive-internal-public-exposure/vulnerable.move")
        result = _run_analysis(files, "sensitive-internal-public-exposure")

        candidates = {c[1] for c in result.candidates}
        assert any("update_reserve_index" in c for c in candidates), \
            f"update_reserve_index should be flagged as candidate: {result.candidates}"

    def test_vulnerable_balance_join_helper(self):
        """Public balance join helper called internally should be flagged."""
        files = _get_fixture_files("sensitive-internal-public-exposure/vulnerable.move")
        result = _run_analysis(files, "sensitive-internal-public-exposure")

        candidates = {c[1] for c in result.candidates}
        assert any("join_vault_balance" in c for c in candidates), \
            f"join_vault_balance should be flagged as candidate: {result.candidates}"

    def test_safe_friend_visibility_not_flagged(self):
        """public(friend) functions should NOT be flagged."""
        files = _get_fixture_files("sensitive-internal-public-exposure/safe.move")
        result = _run_analysis(files, "sensitive-internal-public-exposure")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("do_withdraw_restricted" in fn for fn in all_funcs), \
            f"do_withdraw_restricted should NOT be flagged (public(friend)): {all_funcs}"

    def test_safe_with_capability_not_flagged(self):
        """Functions with capability param should NOT be flagged."""
        files = _get_fixture_files("sensitive-internal-public-exposure/safe.move")
        result = _run_analysis(files, "sensitive-internal-public-exposure")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("admin_withdraw_with_cap" in fn for fn in all_funcs), \
            f"admin_withdraw_with_cap should NOT be flagged (has cap): {all_funcs}"

    def test_safe_no_internal_callers_not_flagged(self):
        """Public functions without internal callers should NOT be flagged."""
        files = _get_fixture_files("sensitive-internal-public-exposure/safe.move")
        result = _run_analysis(files, "sensitive-internal-public-exposure")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("get_vault_balance" in fn for fn in all_funcs), \
            f"get_vault_balance should NOT be flagged (no internal callers, read-only): {all_funcs}"

    def test_safe_factory_pattern_not_flagged(self):
        """Factory functions should NOT be flagged."""
        files = _get_fixture_files("sensitive-internal-public-exposure/safe.move")
        result = _run_analysis(files, "sensitive-internal-public-exposure")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("create_vault" in fn for fn in all_funcs), \
            f"create_vault should NOT be flagged (factory pattern): {all_funcs}"

    def test_safe_entry_caller_not_flagged(self):
        """Entry functions that call helpers should NOT themselves be flagged."""
        files = _get_fixture_files("sensitive-internal-public-exposure/vulnerable.move")
        result = _run_analysis(files, "sensitive-internal-public-exposure")

        # admin_withdraw has a cap param, so it should NOT be flagged
        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("admin_withdraw" == fn.split("::")[-1] for fn in all_funcs), \
            f"admin_withdraw should NOT be flagged (has cap): {all_funcs}"

    def test_multi_hop_internal_caller_detected(self):
        """Multi-hop call chain: bottom_helper called via middle_helper should be flagged.

        Tests that has_internal_callers correctly identifies internal helpers
        even when called indirectly through intermediate functions.
        Call chain: admin_action (with cap) -> middle_helper -> bottom_helper
        """
        files = _get_fixture_files("sensitive-internal-public-exposure/vulnerable.move")
        result = _run_analysis(files, "sensitive-internal-public-exposure")

        candidates = {c[1] for c in result.candidates}
        assert any("bottom_helper" in c for c in candidates), \
            f"bottom_helper (multi-hop) should be flagged as candidate: {result.candidates}"

    def test_multi_hop_middle_helper_not_flagged(self):
        """Middle helper without direct sensitive sink should NOT be flagged.

        Design decision: Only bottom-most helpers with direct sinks are flagged.
        middle_helper has no direct sink (it just calls bottom_helper), so it's not flagged.
        """
        files = _get_fixture_files("sensitive-internal-public-exposure/vulnerable.move")
        result = _run_analysis(files, "sensitive-internal-public-exposure")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("middle_helper" in fn for fn in all_funcs), \
            f"middle_helper should NOT be flagged (no direct sink): {all_funcs}"


class TestCapabilityLeakage:
    """Test capability-leakage rule.

    Detects functions returning or transferring privileged capabilities
    without proper authorization checks.
    """

    def test_returns_reference_to_privileged_type(self):
        """Function returning & to privileged cap should be flagged."""
        files = _get_fixture_files("capability-leakage/reference_return.move")
        result = _run_analysis(files, "capability-leakage")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("get_admin_cap_ref" in fn for fn in all_funcs), \
            f"Expected get_admin_cap_ref to be flagged: {all_funcs}"

    def test_returns_mutable_reference_to_privileged_type(self):
        """Function returning &mut to privileged cap should be flagged."""
        files = _get_fixture_files("capability-leakage/reference_return.move")
        result = _run_analysis(files, "capability-leakage")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("get_admin_cap_mut" in fn for fn in all_funcs), \
            f"Expected get_admin_cap_mut to be flagged: {all_funcs}"

    def test_returns_value_privileged_type(self):
        """Function returning privileged cap by value should be flagged."""
        files = _get_fixture_files("capability-leakage/reference_return.move")
        result = _run_analysis(files, "capability-leakage")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert any("get_admin_cap_value" in fn for fn in all_funcs), \
            f"Expected get_admin_cap_value to be flagged: {all_funcs}"

    def test_guarded_reference_not_flagged(self):
        """Function with cap guard returning reference should NOT be flagged."""
        files = _get_fixture_files("capability-leakage/reference_return.move")
        result = _run_analysis(files, "capability-leakage")

        all_funcs = {v[1] for v in result.violations} | {c[1] for c in result.candidates}
        assert not any("get_admin_cap_guarded" in fn for fn in all_funcs), \
            f"get_admin_cap_guarded should NOT be flagged (has guard): {all_funcs}"

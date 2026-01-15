from pathlib import Path
from typing import List

from core.context import ProjectContext
from analysis import run_structural_analysis, run_fact_propagation
from rules.hy_loader import load_hy_rules
from pipeline import run_filter_pass
from taint.guards import generate_guarded_sink_facts


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "e2e"
RULES_DIR = Path(__file__).parent.parent / "rules"


def _run_analysis(source_files: List[str], rule_filter: str = None):
    """Run analysis pipeline and return violations + candidates."""
    ctx = ProjectContext(source_files)
    run_structural_analysis(ctx)
    run_fact_propagation(ctx)
    generate_guarded_sink_facts(ctx)

    # Load rules
    rules = []
    for rule_file in RULES_DIR.glob("*.hy"):
        rules.extend(load_hy_rules(str(rule_file)))
    if rule_filter:
        rules = [r for r in rules if r.name == rule_filter]

    # Run filter pass
    filter_result = run_filter_pass(ctx, rules)

    # Extract function names
    violations = {item[1].get(item[0].match_binding, "unknown")
                 for item in filter_result.violations}
    candidates = {c.binding.get(c.rule.match_binding, "unknown")
                 for c in filter_result.candidates}

    return violations, candidates


def _get_fixture_files(*paths: str) -> List[str]:
    """Get absolute paths for fixture files."""
    return [str(FIXTURES_DIR / p) for p in paths]


class TestCapabilityLeakage:
    """Test capability-leakage rule.

    Detects public functions that return or transfer privileged capabilities
    to tainted recipients without authorization.
    """

    def test_ipa_transitive_leakage(self):
        """Detect cap leakage through helper chain (IPA test)."""
        files = _get_fixture_files("capability-leakage/ipa_vulnerable.move")
        violations, candidates = _run_analysis(files, "capability-leakage")

        all_funcs = violations | candidates
        # leak_cap_via_helper leaks AdminCap through helper chain
        assert any("leak_cap_via_helper" in fn for fn in all_funcs), \
            f"Expected leak_cap_via_helper to be flagged: {all_funcs}"

    def test_ipa_returns_cap_flagged(self):
        """Function returning privileged cap should be flagged."""
        files = _get_fixture_files("capability-leakage/ipa_vulnerable.move")
        violations, candidates = _run_analysis(files, "capability-leakage")

        all_funcs = violations | candidates
        # get_admin_cap returns AdminCap without auth
        assert any("get_admin_cap" in fn for fn in all_funcs), \
            f"Expected get_admin_cap to be flagged: {all_funcs}"

    def test_ipa_safe_with_auth(self):
        """Cap creation with auth should NOT be flagged."""
        files = _get_fixture_files("capability-leakage/ipa_vulnerable.move")
        violations, candidates = _run_analysis(files, "capability-leakage")

        all_funcs = violations | candidates
        # create_admin_safe requires AdminCap
        assert not any("create_admin_safe" in fn for fn in all_funcs), \
            f"create_admin_safe should NOT be flagged: {all_funcs}"

    def test_cross_module_leakage(self):
        """Detect cap leakage to tainted recipient across modules."""
        files = _get_fixture_files(
            "capability-leakage/cross_module_cap_module.move",
            "capability-leakage/cross_module_leak_module.move",
        )
        violations, candidates = _run_analysis(files, "capability-leakage")

        all_funcs = violations | candidates
        # leak_admin_cross_module leaks AdminCap from cap_module
        assert any("leak_admin_cross_module" in fn for fn in all_funcs), \
            f"Expected leak_admin_cross_module to be flagged: {all_funcs}"

    def test_cross_module_returns_cap_flagged(self):
        """Function returning cap from another module should be flagged."""
        files = _get_fixture_files(
            "capability-leakage/cross_module_cap_module.move",
            "capability-leakage/cross_module_leak_module.move",
        )
        violations, candidates = _run_analysis(files, "capability-leakage")

        all_funcs = violations | candidates
        # get_admin_from_other_module returns AdminCap without auth
        assert any("get_admin_from_other_module" in fn for fn in all_funcs), \
            f"Expected get_admin_from_other_module to be flagged: {all_funcs}"

    def test_cross_module_safe(self):
        """Cross-module with auth should NOT be flagged."""
        files = _get_fixture_files(
            "capability-leakage/cross_module_cap_module.move",
            "capability-leakage/cross_module_leak_module.move",
        )
        violations, candidates = _run_analysis(files, "capability-leakage")

        all_funcs = violations | candidates
        # create_admin_safe uses auth-checked wrapper
        assert not any("create_admin_safe" in fn and "leak_module" in fn
                      for fn in all_funcs), \
            f"create_admin_safe should NOT be flagged: {all_funcs}"

    def test_fqn_collision_privileged_flagged(self):
        """Only privileged cap (module_a::AdminCap) leakage should be flagged."""
        files = _get_fixture_files(
            "capability-leakage/fqn_collision_module_a.move",
            "capability-leakage/fqn_collision_module_b.move",
        )
        violations, candidates = _run_analysis(files, "capability-leakage")

        all_funcs = violations | candidates
        # module_a functions leak privileged module_a::AdminCap
        assert any("module_a" in fn and ("get_admin_cap" in fn or "leak_admin_cap" in fn)
                  for fn in all_funcs), \
            f"Expected module_a cap leakage to be flagged: {all_funcs}"

    def test_fqn_collision_non_privileged_not_flagged(self):
        """Non-privileged cap (module_b::AdminCap) should NOT trigger leakage."""
        files = _get_fixture_files(
            "capability-leakage/fqn_collision_module_a.move",
            "capability-leakage/fqn_collision_module_b.move",
        )
        violations, candidates = _run_analysis(files, "capability-leakage")

        all_funcs = violations | candidates
        # module_b::get_admin_cap returns non-privileged module_b::AdminCap
        assert not any("module_b" in fn and ("get_admin_cap" in fn or "transfer_cap" in fn)
                      and "leak_other" not in fn for fn in all_funcs), \
            f"module_b cap operations should NOT be flagged: {all_funcs}"

    def test_fqn_cross_reference_flagged(self):
        """Leaking module_a cap from module_b should be flagged."""
        files = _get_fixture_files(
            "capability-leakage/fqn_collision_module_a.move",
            "capability-leakage/fqn_collision_module_b.move",
        )
        violations, candidates = _run_analysis(files, "capability-leakage")

        all_funcs = violations | candidates
        # module_b::leak_other_module_cap leaks module_a::AdminCap
        assert any("leak_other_module_cap" in fn for fn in all_funcs), \
            f"Expected leak_other_module_cap to be flagged: {all_funcs}"

    def test_friend_visibility_not_flagged(self):
        """public(friend) functions should NOT be flagged - they're internal."""
        files = _get_fixture_files("capability-leakage/friend_visibility.move")
        violations, candidates = _run_analysis(files, "capability-leakage")

        all_funcs = violations | candidates
        # public(friend) functions should NOT be flagged
        assert not any("new_admin_cap" in fn for fn in all_funcs), \
            f"public(friend) new_admin_cap should NOT be flagged: {all_funcs}"
        assert not any("create_cap_internal" in fn for fn in all_funcs), \
            f"public(friend) create_cap_internal should NOT be flagged: {all_funcs}"

    def test_friend_visibility_public_still_flagged(self):
        """public functions in same file should still be flagged."""
        files = _get_fixture_files("capability-leakage/friend_visibility.move")
        violations, candidates = _run_analysis(files, "capability-leakage")

        all_funcs = violations | candidates
        # public function should still be flagged
        assert any("get_admin_cap_public" in fn for fn in all_funcs), \
            f"public get_admin_cap_public SHOULD be flagged: {all_funcs}"


class TestCrossUserAssetTheft:
    """Test cross-user-asset-theft rule.

    Detects public entry functions that access user assets without
    verifying caller ownership.
    """

    def test_ipa_transitive_asset_access(self):
        """Detect asset access without ownership through helpers (IPA test)."""
        files = _get_fixture_files("cross-user-asset-theft/ipa_vulnerable.move")
        violations, candidates = _run_analysis(files, "cross-user-asset-theft")

        all_funcs = violations | candidates
        # steal_via_helper accesses Vault without ownership check via helpers
        assert any("steal_via_helper" in fn for fn in all_funcs), \
            f"Expected steal_via_helper to be flagged: {all_funcs}"

    def test_ipa_direct_theft_flagged(self):
        """Direct theft without ownership check should be flagged."""
        files = _get_fixture_files("cross-user-asset-theft/ipa_vulnerable.move")
        violations, candidates = _run_analysis(files, "cross-user-asset-theft")

        all_funcs = violations | candidates
        # steal_direct accesses Vault without ownership check
        assert any("steal_direct" in fn for fn in all_funcs), \
            f"Expected steal_direct to be flagged: {all_funcs}"

    def test_ipa_safe_with_ownership_check(self):
        """Access with ownership verification should NOT be flagged."""
        files = _get_fixture_files("cross-user-asset-theft/ipa_vulnerable.move")
        violations, candidates = _run_analysis(files, "cross-user-asset-theft")

        all_funcs = violations | candidates
        # withdraw_safe verifies ownership
        assert not any("withdraw_safe" in fn for fn in all_funcs), \
            f"withdraw_safe should NOT be flagged: {all_funcs}"

    def test_ipa_safe_with_admin(self):
        """Access with admin cap should NOT be flagged."""
        files = _get_fixture_files("cross-user-asset-theft/ipa_vulnerable.move")
        violations, candidates = _run_analysis(files, "cross-user-asset-theft")

        all_funcs = violations | candidates
        # withdraw_admin has AdminCap parameter
        assert not any("withdraw_admin" in fn for fn in all_funcs), \
            f"withdraw_admin should NOT be flagged: {all_funcs}"

    def test_ipa_safe_deposit(self):
        """Deposit (transfers FROM sender) should NOT be flagged."""
        files = _get_fixture_files("cross-user-asset-theft/ipa_vulnerable.move")
        violations, candidates = _run_analysis(files, "cross-user-asset-theft")

        all_funcs = violations | candidates
        # deposit is safe (user deposits own funds)
        assert not any("deposit" in fn for fn in all_funcs), \
            f"deposit should NOT be flagged: {all_funcs}"

    def test_cross_module_asset_access(self):
        """Detect asset theft across module boundaries."""
        files = _get_fixture_files(
            "cross-user-asset-theft/cross_module_vault_module.move",
            "cross-user-asset-theft/cross_module_theft_module.move",
        )
        violations, candidates = _run_analysis(files, "cross-user-asset-theft")

        all_funcs = violations | candidates
        # steal_cross_module accesses Vault from vault_module without ownership check
        assert any("steal_cross_module" in fn for fn in all_funcs), \
            f"Expected steal_cross_module to be flagged: {all_funcs}"

    def test_cross_module_safe_with_verification(self):
        """Cross-module with ownership verification should NOT be flagged."""
        files = _get_fixture_files(
            "cross-user-asset-theft/cross_module_vault_module.move",
            "cross-user-asset-theft/cross_module_theft_module.move",
        )
        violations, candidates = _run_analysis(files, "cross-user-asset-theft")

        all_funcs = violations | candidates
        # withdraw_safe_cross_module verifies ownership via vault_module::verify_owner
        assert not any("withdraw_safe_cross_module" in fn for fn in all_funcs), \
            f"withdraw_safe_cross_module should NOT be flagged: {all_funcs}"

    def test_fqn_collision_user_asset_flagged(self):
        """Only user asset (module_a::Vault) theft should be flagged."""
        files = _get_fixture_files(
            "cross-user-asset-theft/fqn_collision_module_a.move",
            "cross-user-asset-theft/fqn_collision_module_b.move",
        )
        violations, candidates = _run_analysis(files, "cross-user-asset-theft")

        all_funcs = violations | candidates
        # module_a::steal_from_vault accesses user asset module_a::Vault
        assert any("module_a" in fn and "steal_from_vault" in fn for fn in all_funcs), \
            f"Expected module_a::steal_from_vault to be flagged: {all_funcs}"

    def test_fqn_collision_protocol_state_different_rule(self):
        """Protocol state (module_b::Vault) is NOT user asset theft.

        module_b::withdraw_from_vault may be flagged by missing-authorization,
        but NOT by cross-user-asset-theft (it's protocol state, not user asset).
        """
        files = _get_fixture_files(
            "cross-user-asset-theft/fqn_collision_module_a.move",
            "cross-user-asset-theft/fqn_collision_module_b.move",
        )
        violations, candidates = _run_analysis(files, "cross-user-asset-theft")

        all_funcs = violations | candidates
        # module_b::withdraw_from_vault accesses protocol state (module_b::Vault)
        # Should NOT be flagged by cross-user-asset-theft
        assert not any("module_b" in fn and "withdraw_from_vault" in fn
                      for fn in all_funcs), \
            f"module_b::withdraw_from_vault should NOT be flagged (protocol state): {all_funcs}"

    def test_fqn_cross_reference_theft_flagged(self):
        """Stealing from module_a::Vault (user asset) from module_b should be flagged."""
        files = _get_fixture_files(
            "cross-user-asset-theft/fqn_collision_module_a.move",
            "cross-user-asset-theft/fqn_collision_module_b.move",
        )
        violations, candidates = _run_analysis(files, "cross-user-asset-theft")

        all_funcs = violations | candidates
        # module_b::steal_from_module_a accesses module_a::Vault (user asset)
        assert any("steal_from_module_a" in fn for fn in all_funcs), \
            f"Expected steal_from_module_a to be flagged: {all_funcs}"

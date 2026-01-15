"""End-to-end integration tests for taint-based Hy rules.

Tests that actual taint flows trigger the appropriate rules.
"""

import textwrap
import tempfile
import os

import pytest

from core.context import ProjectContext
from analysis import StructuralBuilder
from taint import run_structural_taint_analysis
from rules.hy_loader import HyRule, load_hy_rules
from rules.eval_context import EvalContext
from rules.ir import Severity, Binding


class TestTaintRuleIntegration:
    """Integration tests for taint-based security rules."""

    def _create_temp_move_file(self, content: str) -> str:
        """Create a temporary Move file with given content."""
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, "w") as f:
            f.write(textwrap.dedent(content))
        return path

    def _run_rules_on_source(self, source: str, rule_file: str = None, rules: list = None) -> list:
        """Run rules against source and return (rule_name, binding) tuples."""
        path = self._create_temp_move_file(source)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)
            run_structural_taint_analysis(ctx)

            file_ctx = ctx.source_files[path]
            facts = file_ctx.facts

            if rules is None:
                if rule_file:
                    rules = load_hy_rules(rule_file)
                else:
                    rules = []

            violations = []

            eval_ctx = EvalContext(
                ctx=ctx,
                current_file=path,
                current_source=file_ctx.source_code,
                current_root=file_ctx.root,
            )

            for rule in rules:
                bindings = self._find_bindings(rule, facts)

                for binding in bindings:
                    bound_value = binding.get("f") or binding.get("r") or binding.get("e")
                    try:
                        # Filter clause check
                        if rule.filter_clause and not rule.filter_clause(bound_value, facts, eval_ctx):
                            continue
                        # Classify clause check (if present)
                        if rule.classify_clause:
                            if rule.classify_clause(bound_value, facts, eval_ctx):
                                violations.append((rule.name, binding))
                        else:
                            # Filter-only rule
                            violations.append((rule.name, binding))
                    except Exception:
                        pass

            return violations
        finally:
            os.unlink(path)

    def _find_bindings(self, rule: HyRule, facts: list) -> list:
        """Find bindings for a Hy rule based on its match pattern."""
        from core.facts import get_caps, get_events

        bindings = []
        pattern = rule.match_pattern
        modifiers = rule.match_modifiers
        binding_name = rule.match_binding

        if pattern == "fun":
            for fact in facts:
                if fact.name != "Fun":
                    continue
                func_name = fact.args[0]

                if "public" in modifiers:
                    if not any(f.name == "IsPublic" and f.args[0] == func_name for f in facts):
                        continue
                if "entry" in modifiers:
                    if not any(f.name == "IsEntry" and f.args[0] == func_name for f in facts):
                        continue

                bindings.append(Binding({binding_name: func_name}))

        elif pattern == "role":
            roles = get_caps(facts)
            for role_name in roles:
                bindings.append(Binding({binding_name: role_name}))

        elif pattern == "event":
            events = get_events(facts)
            for event_name in events:
                bindings.append(Binding({binding_name: event_name}))

        return bindings

    def _make_taint_rule(self, name: str, predicate, severity: Severity = Severity.HIGH) -> HyRule:
        """Create a taint-checking HyRule."""
        return HyRule(
            name=name,
            severity=severity,
            match_pattern="fun",
            match_modifiers=["public", "entry"],
            match_binding="f",
            filter_clause=predicate,
        )

    # =========================================================================
    # Tainted Recipient Tests
    # =========================================================================

    def test_tainted_recipient_detected(self):
        """User-controlled recipient in transfer is detected."""
        source = """
            module test::vuln {
                use sui::transfer;
                use sui::coin::{Self, Coin};
                use sui::sui::SUI;
                use sui::tx_context::TxContext;

                public entry fun drain(coin: Coin<SUI>, recipient: address) {
                    transfer::public_transfer(coin, recipient);
                }
            }
        """

        # Check for TaintedAtSink fact with sink_type='transfer_recipient'
        def predicate(f, facts, ctx):
            return any(
                fact.name == "TaintedAtSink" and
                fact.args[0] == f and
                fact.args[3] == "transfer_recipient"
                for fact in facts
            )

        rule = self._make_taint_rule("tainted_recipient", predicate)
        violations = self._run_rules_on_source(source, rules=[rule])

        assert len(violations) == 1
        assert "drain" in violations[0][1]["f"]

    def test_tainted_recipient_safe_with_hardcoded_address(self):
        """Hardcoded address is NOT tainted."""
        source = """
            module test::safe {
                use sui::transfer;
                use sui::coin::{Self, Coin};
                use sui::sui::SUI;

                const TREASURY: address = @0x123;

                public entry fun safe_transfer(coin: Coin<SUI>) {
                    transfer::public_transfer(coin, TREASURY);
                }
            }
        """

        def predicate(f, facts, ctx):
            return any(
                fact.name == "TaintedAtSink" and
                fact.args[0] == f and
                fact.args[3] == "transfer_recipient"
                for fact in facts
            )

        rule = self._make_taint_rule("tainted_recipient", predicate)
        violations = self._run_rules_on_source(source, rules=[rule])

        # Should NOT trigger - address is hardcoded constant
        assert len(violations) == 0

    def test_tainted_recipient_with_sender(self):
        """tx_context::sender does NOT generate TaintedTransferRecipient fact.

        Reference params (&TxContext) are not taint sources - they represent
        object access, not user-provided data. sender(ctx) returns the caller's
        own address, which is safe (user withdrawing to themselves).
        """
        source = """
            module test::safe {
                use sui::transfer;
                use sui::coin::{Self, Coin};
                use sui::sui::SUI;
                use sui::tx_context::{Self, TxContext};

                public entry fun withdraw_to_self(coin: Coin<SUI>, ctx: &TxContext) {
                    transfer::public_transfer(coin, tx_context::sender(ctx));
                }
            }
        """

        def predicate(f, facts, ctx):
            return any(
                fact.name == "TaintedAtSink" and
                fact.args[0] == f and
                fact.args[3] == "transfer_recipient"
                for fact in facts
            )

        rule = self._make_taint_rule("tainted_recipient", predicate)
        violations = self._run_rules_on_source(source, rules=[rule])

        # ctx is &TxContext (reference), not a taint source
        # sender(ctx) is not tainted, so no TaintedTransferRecipient
        assert len(violations) == 0

    # =========================================================================
    # Tainted Amount Tests
    # =========================================================================

    def test_tainted_amount_detected(self):
        """User-controlled amount in coin::take is detected."""
        source = """
            module test::vuln {
                use sui::coin::{Self, Coin};
                use sui::balance::{Self, Balance};
                use sui::sui::SUI;
                use sui::tx_context::TxContext;
                use sui::transfer;

                struct Vault has key {
                    id: UID,
                    balance: Balance<SUI>
                }

                public entry fun withdraw(vault: &mut Vault, amount: u64, ctx: &mut TxContext) {
                    let coins = coin::take(&mut vault.balance, amount, ctx);
                    transfer::public_transfer(coins, tx_context::sender(ctx));
                }
            }
        """

        # Check for TaintedAtSink fact with sink_type='amount_extraction'
        def predicate(f, facts, ctx):
            return any(
                fact.name == "TaintedAtSink" and
                fact.args[0] == f and
                fact.args[3] == "amount_extraction"
                for fact in facts
            )

        rule = self._make_taint_rule("tainted_amount", predicate)
        violations = self._run_rules_on_source(source, rules=[rule])

        assert len(violations) == 1
        assert "withdraw" in violations[0][1]["f"]

    # =========================================================================
    # Tainted State Write Tests
    # =========================================================================

    def test_tainted_state_write_detected(self):
        """User-controlled data written to state is detected via Tainted facts.

        Note: TaintedStateWrite is generated by semantic checks, not structural analysis.
        At the structural level, we have Tainted facts for the variables.
        """
        source = """
            module test::vuln {
                use sui::object::UID;

                struct Config has key {
                    id: UID,
                    admin: address
                }

                public entry fun set_admin(config: &mut Config, new_admin: address) {
                    config.admin = new_admin;
                }
            }
        """

        # Check that the new_admin parameter is tainted (user input)
        def predicate(f, facts, ctx):
            return any(
                fact.name == "Tainted" and fact.args[0] == f and "new_admin" in str(fact.args)
                for fact in facts
            )

        rule = self._make_taint_rule("tainted_input", predicate)
        violations = self._run_rules_on_source(source, rules=[rule])

        assert len(violations) == 1
        assert "set_admin" in violations[0][1]["f"]

    # =========================================================================
    # Combined Rule Tests (Real Rules from rules/)
    # =========================================================================

    def test_access_control_rules_detect_vulnerable_withdraw(self):
        """Access control rules detect unprotected value transfer."""
        source = """
            module test::vuln {
                use sui::transfer;
                use sui::coin::{Self, Coin};
                use sui::balance::{Self, Balance};
                use sui::sui::SUI;
                use sui::tx_context::{Self, TxContext};
                use sui::object::UID;

                struct Vault has key {
                    id: UID,
                    balance: Balance<SUI>
                }

                public entry fun withdraw(vault: &mut Vault, amount: u64, recipient: address, ctx: &mut TxContext) {
                    let coins = coin::take(&mut vault.balance, amount, ctx);
                    transfer::public_transfer(coins, recipient);
                }
            }
        """

        violations = self._run_rules_on_source(source, rule_file="rules/access_control.hy")

        # Should detect at least one violation (tainted recipient, tainted amount, etc.)
        assert len(violations) > 0
        violation_names = {v[0] for v in violations}
        # Could be arbitrary-recipient-drain or tainted-amount-drain
        assert any(
            "drain" in name or "tainted" in name
            for name in violation_names
        )

    def test_safe_function_no_violations(self):
        """Function with proper access control should not trigger."""
        source = """
            module test::safe {
                use sui::transfer;
                use sui::coin::{Self, Coin};
                use sui::balance::{Self, Balance};
                use sui::sui::SUI;
                use sui::tx_context::{Self, TxContext};
                use sui::object::UID;

                struct AdminCap has key, store {
                    id: UID
                }

                struct Vault has key {
                    id: UID,
                    balance: Balance<SUI>
                }

                public entry fun admin_withdraw(
                    _cap: &AdminCap,
                    vault: &mut Vault,
                    amount: u64,
                    recipient: address,
                    ctx: &mut TxContext
                ) {
                    let coins = coin::take(&mut vault.balance, amount, ctx);
                    transfer::public_transfer(coins, recipient);
                }
            }
        """

        violations = self._run_rules_on_source(source, rule_file="rules/access_control.hy")

        # Filter out false positives - admin_withdraw has AdminCap check
        func_violations = [v for v in violations if "admin_withdraw" in v[1].get("f", "")]

        # Rules that check for caps should NOT fire on admin_withdraw
        # (though some rules may still fire if they don't check for caps)
        # The important thing is that checks-role aware rules don't fire
        checks_role_rules = ["arbitrary-recipient-drain"]
        for violation in func_violations:
            # These specific rules should NOT fire on admin_withdraw
            if violation[0] in checks_role_rules:
                # If they do, this test fails
                pytest.fail(f"Rule {violation[0]} should not fire on admin_withdraw with AdminCap")


class TestTaintFactGeneration:
    """Test that taint facts are correctly generated."""

    def _create_temp_move_file(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, "w") as f:
            f.write(textwrap.dedent(content))
        return path

    def _get_facts(self, source: str) -> list:
        """Parse source and return facts."""
        path = self._create_temp_move_file(source)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)
            run_structural_taint_analysis(ctx)
            return ctx.source_files[path].facts
        finally:
            os.unlink(path)

    def test_tainted_transfer_recipient_fact(self):
        """TaintedTransferRecipient fact is generated for user-controlled recipient."""
        source = """
            module test::example {
                use sui::transfer;
                use sui::coin::Coin;
                use sui::sui::SUI;

                public entry fun send(coin: Coin<SUI>, to: address) {
                    transfer::public_transfer(coin, to);
                }
            }
        """

        facts = self._get_facts(source)
        taint_facts = [f for f in facts if "Taint" in f.name]

        assert any(f.name == "TaintedAtSink" for f in taint_facts), \
            f"Expected TaintedTransferRecipient fact, got: {[f.name for f in taint_facts]}"

    def test_tainted_amount_extraction_fact(self):
        """TaintedAmountExtraction fact is generated for user-controlled amount."""
        source = """
            module test::example {
                use sui::coin;
                use sui::balance::Balance;
                use sui::sui::SUI;
                use sui::tx_context::TxContext;

                struct Pool has key {
                    id: UID,
                    balance: Balance<SUI>
                }

                public entry fun take(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
                    let c = coin::take(&mut pool.balance, amount, ctx);
                }
            }
        """

        facts = self._get_facts(source)
        taint_facts = [f for f in facts if "Taint" in f.name]

        assert any(f.name == "TaintedAtSink" for f in taint_facts), \
            f"Expected TaintedAmountExtraction fact, got: {[f.name for f in taint_facts]}"

    def test_tainted_parameter_fact(self):
        """Tainted fact is generated for user-controlled parameters."""
        source = """
            module test::example {
                use sui::object::UID;

                struct State has key {
                    id: UID,
                    value: u64
                }

                public entry fun set_value(state: &mut State, new_value: u64) {
                    state.value = new_value;
                }
            }
        """

        facts = self._get_facts(source)
        taint_facts = [f for f in facts if f.name == "Tainted"]

        # new_value parameter should be marked as tainted
        assert any("new_value" in str(f.args) for f in taint_facts), \
            f"Expected Tainted fact for new_value, got: {taint_facts}"

    def test_taint_for_internal_function(self):
        """Private functions also get taint facts (conservative analysis).

        Note: The current taint analysis is conservative and marks all function
        parameters as taint sources, regardless of visibility. This is because
        private functions can be called with tainted data from public functions.
        The higher-level rules filter based on function visibility.
        """
        source = """
            module test::example {
                use sui::transfer;
                use sui::coin::Coin;
                use sui::sui::SUI;

                fun internal_send(coin: Coin<SUI>, to: address) {
                    transfer::public_transfer(coin, to);
                }
            }
        """

        facts = self._get_facts(source)

        # Private functions still get taint facts (conservative analysis)
        # This is intentional - the rules filter by visibility
        taint_recipient_facts = [
            f for f in facts
            if f.name == "TaintedAtSink" and "internal_send" in str(f.args)
        ]
        assert len(taint_recipient_facts) > 0, \
            "Taint analysis should be conservative and mark private function params as tainted"

    def test_tainted_state_write_fact_via_dynamic_field(self):
        """TaintedStateWrite fact is generated for dynamic_field operations."""
        source = """
            module test::example {
                use sui::dynamic_field;
                use sui::object::UID;

                struct Config has key {
                    id: UID
                }

                public entry fun update_config(config: &mut Config, key: vector<u8>, value: u64) {
                    dynamic_field::add(&mut config.id, key, value);
                }
            }
        """

        facts = self._get_facts(source)
        tainted_state_writes = [f for f in facts if f.name == "TaintedAtSink"]

        assert len(tainted_state_writes) > 0, \
            f"Expected TaintedStateWrite fact for dynamic_field::add, got facts: {[f.name for f in facts if 'Taint' in f.name or 'Sink' in f.name]}"


class TestHyBridgeTaintChecks:
    """Test that Hy bridge correctly calls taint check functions.

    These tests specifically verify that the MinimalRule/MinimalPattern duck-typing
    works correctly when calling Python semantic checks from Hy rules.
    """

    def _create_temp_move_file(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, "w") as f:
            f.write(textwrap.dedent(content))
        return path

    def _get_context_and_facts(self, source: str):
        """Parse source and return (ctx, path, facts)."""
        path = self._create_temp_move_file(source)
        ctx = ProjectContext([path])
        StructuralBuilder().build(ctx)
        run_structural_taint_analysis(ctx)
        facts = ctx.source_files[path].facts
        return ctx, path, facts

    def test_tainted_state_write_via_hy_bridge(self):
        """Test that tainted_state_write check works via Hy bridge.

        This test verifies the fix for the MinimalPattern duck-typing issue
        where get_function_binding_key() returned None because it only checked
        for isinstance(pattern, FunPattern) and not for MinimalPattern.
        """
        source = """
            module test::example {
                use sui::dynamic_field;
                use sui::object::UID;

                struct Config has key {
                    id: UID
                }

                public entry fun update_fee(config: &mut Config, fee: u64) {
                    dynamic_field::add(&mut config.id, b"fee", fee);
                }
            }
        """

        ctx, path, facts = self._get_context_and_facts(source)

        try:
            # Import the bridge function
            from rules.hy_bridge import call_check
            from rules.eval_context import EvalContext

            eval_ctx = EvalContext(
                ctx=ctx,
                current_file=path,
                current_source=ctx.source_files[path].source_code,
                current_root=ctx.source_files[path].root,
            )

            func_name = "test::example::update_fee"

            # Call tainted_state_write via the bridge
            result = call_check("tainted_state_write", func_name, facts, eval_ctx)

            # Should return True because:
            # 1. fee parameter is tainted (user input)
            # 2. dynamic_field::add is a state write sink
            # 3. TaintedStateWrite fact should be generated
            assert result is True, \
                f"tainted_state_write should return True for {func_name}, but returned {result}"
        finally:
            os.unlink(path)

    def test_tainted_recipient_via_hy_bridge(self):
        """Test that tainted_recipient check works via Hy bridge.

        Note: The tainted_recipient check has a filter for user-owned Coin/Balance
        parameters (safe because user is transferring their own assets). So we need
        to test with a case where the VALUE comes from protocol storage, not user input.
        """
        source = """
            module test::example {
                use sui::transfer;
                use sui::coin::{Self, Coin};
                use sui::balance::Balance;
                use sui::sui::SUI;
                use sui::tx_context::TxContext;
                use sui::object::UID;

                struct Vault has key {
                    id: UID,
                    balance: Balance<SUI>
                }

                public entry fun drain(vault: &mut Vault, recipient: address, ctx: &mut TxContext) {
                    let coins = coin::take(&mut vault.balance, 1000, ctx);
                    transfer::public_transfer(coins, recipient);
                }
            }
        """

        ctx, path, facts = self._get_context_and_facts(source)

        try:
            from rules.hy_bridge import call_check
            from rules.eval_context import EvalContext

            eval_ctx = EvalContext(
                ctx=ctx,
                current_file=path,
                current_source=ctx.source_files[path].source_code,
                current_root=ctx.source_files[path].root,
            )

            func_name = "test::example::drain"
            result = call_check("tainted_recipient", func_name, facts, eval_ctx)

            # Should return True because:
            # 1. recipient is user-controlled (tainted)
            # 2. The value being transferred comes from protocol storage (not user's own asset)
            assert result is True, \
                f"tainted_recipient should return True for {func_name}"
        finally:
            os.unlink(path)

    def test_checks_capability_via_hy_bridge(self):
        """Test that checks_capability check works via Hy bridge."""
        source = """
            module test::example {
                use sui::object::UID;

                struct AdminCap has key {
                    id: UID
                }

                fun init(ctx: &mut TxContext) {
                    let cap = AdminCap { id: object::new(ctx) };
                    transfer::transfer(cap, tx_context::sender(ctx));
                }

                public entry fun admin_action(_cap: &AdminCap) {
                    // Protected by AdminCap
                }

                public entry fun unprotected_action() {
                    // No protection
                }
            }
        """

        ctx, path, facts = self._get_context_and_facts(source)

        try:
            from rules.hy_bridge import call_check
            from rules.eval_context import EvalContext

            eval_ctx = EvalContext(
                ctx=ctx,
                current_file=path,
                current_source=ctx.source_files[path].source_code,
                current_root=ctx.source_files[path].root,
            )

            # admin_action should have ChecksCapability
            result_admin = call_check("checks_capability", "test::example::admin_action", facts, eval_ctx)
            assert result_admin is True, "admin_action should check capability (has AdminCap param)"

            # unprotected_action should NOT have ChecksCapability
            result_unprotected = call_check("checks_capability", "test::example::unprotected_action", facts, eval_ctx)
            assert result_unprotected is False, "unprotected_action should not check capability"
        finally:
            os.unlink(path)

    def test_is_init_via_hy_bridge(self):
        """Test that is_init check works via Hy bridge."""
        source = """
            module test::example {
                use sui::tx_context::TxContext;

                fun init(ctx: &mut TxContext) {
                    // Module initializer
                }

                public entry fun regular_func() {
                    // Not init
                }
            }
        """

        ctx, path, facts = self._get_context_and_facts(source)

        try:
            from rules.hy_bridge import call_check
            from rules.eval_context import EvalContext

            eval_ctx = EvalContext(
                ctx=ctx,
                current_file=path,
                current_source=ctx.source_files[path].source_code,
                current_root=ctx.source_files[path].root,
            )

            # init should be detected as init function
            result_init = call_check("is_init", "test::example::init", facts, eval_ctx)
            assert result_init is True, "init should be detected as init function"

            # regular_func should NOT be init
            result_regular = call_check("is_init", "test::example::regular_func", facts, eval_ctx)
            assert result_regular is False, "regular_func should not be init"
        finally:
            os.unlink(path)

"""Integration tests for Hy rules - end-to-end rule evaluation."""
import textwrap
import tempfile
import os
import sys

sys.path.insert(0, "src")

from core.context import ProjectContext
from analysis import StructuralBuilder
from core.facts import get_caps, get_events
from rules.hy_loader import HyRule, load_hy_rules
from rules.eval_context import EvalContext
from test_utils import make_hy_rule, find_hy_bindings


def _create_temp_move_file(content: str) -> str:
    """Create a temporary Move file with the given content."""
    fd, path = tempfile.mkstemp(suffix=".move")
    with os.fdopen(fd, "w") as f:
        f.write(textwrap.dedent(content))
    return path


def _run_rule(source: str, rule: HyRule):
    """Run a rule against source and return violations."""
    path = _create_temp_move_file(source)
    try:
        ctx = ProjectContext([path])
        StructuralBuilder().build(ctx)

        file_ctx = ctx.source_files[path]
        facts = file_ctx.facts

        bindings = find_hy_bindings(rule, facts)

        if not bindings:
            return []

        eval_ctx = EvalContext(
            ctx=ctx,
            current_file=path,
            current_source=file_ctx.source_code,
            current_root=file_ctx.root,
        )

        violations = []
        for binding in bindings:
            entity_name = binding.get(rule.match_binding)
            try:
                # Filter clause check
                if rule.filter_clause and not rule.filter_clause(entity_name, facts, eval_ctx):
                    continue
                # Classify clause check (if present)
                if rule.classify_clause:
                    if rule.classify_clause(entity_name, facts, eval_ctx):
                        violations.append(binding)
                else:
                    # Filter-only rule
                    violations.append(binding)
            except Exception:
                pass

        return violations
    finally:
        os.unlink(path)


class TestHyRuleLoading:
    """Test that Hy rules load correctly."""

    def test_load_access_control_rules(self):
        """Load access control rules from rules directory."""
        rules = load_hy_rules("rules/access_control.hy")
        assert len(rules) >= 1
        rule_names = [r.name for r in rules]
        assert "arbitrary-recipient-drain" in rule_names

    def test_load_structural_rules(self):
        """Load structural rules."""
        rules = load_hy_rules("rules/structural.hy")
        assert len(rules) >= 1
        rule_names = [r.name for r in rules]
        assert "double-init" in rule_names

    def test_load_code_quality_rules(self):
        """Load code quality rules."""
        rules = load_hy_rules("rules/code_quality.hy")
        assert len(rules) >= 1
        rule_names = [r.name for r in rules]
        assert "orphan-capability" in rule_names


class TestEndToEndRuleEvaluation:
    """End-to-end tests for rule evaluation pipeline."""

    def test_public_entry_function_match(self):
        """Match public entry functions - modifier filtering works."""
        source = """
            module test::example {
                public entry fun vulnerable(x: u64, recipient: address) {
                    transfer::transfer(x, recipient);
                }
                public fun not_entry(x: u64) {
                    do_something(x);
                }
                entry fun not_public(x: u64) {
                    do_other(x);
                }
            }
        """

        # Simple predicate that always returns True - test modifier filtering
        rule = make_hy_rule(
            name="public-entry-check",
            predicate=lambda f, facts, ctx: True,
            match_modifiers=["public", "entry"],
        )

        violations = _run_rule(source, rule)

        # Only one function is both public AND entry
        assert len(violations) == 1
        assert violations[0]["f"] == "test::example::vulnerable"

    def test_no_violation_when_condition_false(self):
        """No violation when predicate returns False."""
        source = """
            module test::example {
                public entry fun safe_func(x: u64) {}
            }
        """

        # Predicate that always returns False
        rule = make_hy_rule(
            name="check",
            predicate=lambda f, facts, ctx: False,
            match_modifiers=["public", "entry"],
        )

        violations = _run_rule(source, rule)
        assert len(violations) == 0

    def test_admin_cap_detection(self):
        """Detect functions with admin capability parameters (ChecksCapability fact)."""
        source = """
            module test::example {
                public struct AdminCap has key {
                    id: UID,
                }

                fun init(ctx: &mut TxContext) {
                    let cap = AdminCap { id: object::new(ctx) };
                    transfer::transfer(cap, tx_context::sender(ctx));
                }

                public fun admin_only(cap: &AdminCap) {
                    // privileged operation
                }

                public fun public_func(x: u64) {
                    // public operation
                }
            }
        """

        def checks_role(f, facts, ctx):
            # ChecksCapability is stored in global_facts_index with args (role_name, func_name)
            # Also check local facts from global index
            func_facts = ctx.ctx.global_facts_index.get(f, {})
            for file_facts in func_facts.values():
                for fact in file_facts:
                    if fact.name == "ChecksCapability" and fact.args[1] == f:
                        return True
            return False

        rule = make_hy_rule(
            name="admin-func",
            predicate=checks_role,
            match_modifiers=["public"],
        )

        violations = _run_rule(source, rule)

        func_names = [v["f"] for v in violations]
        assert "test::example::admin_only" in func_names


class TestRuleMatchWithStatements:
    """Test rules that match functions."""

    def test_match_public_entry_functions(self):
        """Match public entry functions only."""
        source = """
            module test::example {
                public entry fun func1() {
                    do_something();
                }
                public entry fun func2() {
                    do_other();
                }
                public fun not_entry() {
                    also_call();
                }
            }
        """
        path = _create_temp_move_file(source)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            rule = make_hy_rule(
                name="find-entry",
                predicate=lambda f, facts, ctx: True,
                match_modifiers=["public", "entry"],
            )

            file_ctx = ctx.source_files[path]
            bindings = find_hy_bindings(rule, file_ctx.facts)

            func_names = {b["f"] for b in bindings}
            assert "test::example::func1" in func_names
            assert "test::example::func2" in func_names
            assert "test::example::not_entry" not in func_names
        finally:
            os.unlink(path)


class TestChecksCapabilityIntegration:
    """Test ChecksCapability-based rules."""

    def test_checks_role_fact_generated(self):
        """ChecksCapability fact should be generated for functions with role params."""
        source = """
            module test::example {
                public struct AdminCap has key {
                    id: UID,
                }

                fun init(ctx: &mut TxContext) {
                    let cap = AdminCap { id: object::new(ctx) };
                    transfer::transfer(cap, tx_context::sender(ctx));
                }

                public fun withdraw(cap: &AdminCap, amount: u64) {
                    // privileged withdrawal
                }

                public fun deposit(amount: u64) {
                    // anyone can deposit
                }
            }
        """
        path = _create_temp_move_file(source)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            # ChecksCapability should be in global index for withdraw
            withdraw_facts = ctx.global_facts_index.get(
                "test::example::withdraw", {}
            ).get(path, [])
            checks_role = [f for f in withdraw_facts if f.name == "ChecksCapability"]
            assert len(checks_role) == 1

            # deposit should NOT have ChecksCapability
            deposit_facts = ctx.global_facts_index.get(
                "test::example::deposit", {}
            ).get(path, [])
            deposit_checks = [f for f in deposit_facts if f.name == "ChecksCapability"]
            assert len(deposit_checks) == 0
        finally:
            os.unlink(path)


class TestCapabilityPatternMatching:
    """Test capability pattern matching in Hy rules."""

    def test_capability_pattern_finds_capabilities(self):
        """Capability pattern should find capabilities (single UID + admin name + init transfer)."""
        source = """
            module test::example {
                public struct AdminCap has key {
                    id: UID,
                }

                public struct OwnerCap has key {
                    id: UID,
                }

                public struct NotARole has key {
                    id: UID,
                    extra_field: u64,
                }

                fun init(ctx: &mut TxContext) {
                    let admin = AdminCap { id: object::new(ctx) };
                    let owner = OwnerCap { id: object::new(ctx) };
                    transfer::transfer(admin, tx_context::sender(ctx));
                    transfer::transfer(owner, tx_context::sender(ctx));
                }
            }
        """
        path = _create_temp_move_file(source)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            facts = ctx.source_files[path].facts
            caps = get_caps(facts)

            # Should find AdminCap and OwnerCap (single UID field)
            assert "test::example::AdminCap" in caps
            assert "test::example::OwnerCap" in caps
        finally:
            os.unlink(path)


class TestEventPatternMatching:
    """Test event pattern matching."""

    def test_event_pattern_finds_events(self):
        """Event pattern should find all event structs."""
        source = """
            module test::example {
                public struct TransferEvent has copy, drop {
                    from: address,
                    to: address,
                    amount: u64,
                }

                public struct AdminCap has key {
                    id: UID,
                }
            }
        """
        path = _create_temp_move_file(source)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            facts = ctx.source_files[path].facts
            events = get_events(facts)

            # TransferEvent should be detected as event (copy, drop, no key)
            assert "test::example::TransferEvent" in events
            # AdminCap is not an event (has key)
            assert "test::example::AdminCap" not in events
        finally:
            os.unlink(path)


class TestCallDetection:
    """Test call detection facts."""

    def test_call_facts_generated(self):
        """Call facts should be generated for function calls."""
        source = """
            module test::example {
                public entry fun do_stuff() {
                    transfer::public_transfer(x, recipient);
                    coin::take(balance, amount, ctx);
                }
            }
        """
        path = _create_temp_move_file(source)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            facts = ctx.source_files[path].facts
            call_facts = [f for f in facts if f.name == "Call"]

            # Call facts have structure: Call(call_id) where call_id is "callee@counter"
            call_ids = [f.args[0] for f in call_facts]
            assert any("transfer::public_transfer" in c for c in call_ids)
            assert any("coin::take" in c for c in call_ids)
        finally:
            os.unlink(path)


class TestFactsGeneration:
    """Test that basic facts are correctly generated."""

    def test_fun_fact_generated(self):
        """Fun fact should be generated for functions."""
        source = """
            module test::example {
                public entry fun my_function() {}
            }
        """
        path = _create_temp_move_file(source)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            facts = ctx.source_files[path].facts
            fun_facts = [f for f in facts if f.name == "Fun"]
            func_names = [f.args[0] for f in fun_facts]

            assert "test::example::my_function" in func_names
        finally:
            os.unlink(path)

    def test_is_public_fact_generated(self):
        """IsPublic fact should be generated for public functions."""
        source = """
            module test::example {
                public fun public_one() {}
                fun private_one() {}
            }
        """
        path = _create_temp_move_file(source)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            facts = ctx.source_files[path].facts
            public_facts = [f for f in facts if f.name == "IsPublic"]
            public_funcs = [f.args[0] for f in public_facts]

            assert "test::example::public_one" in public_funcs
            assert "test::example::private_one" not in public_funcs
        finally:
            os.unlink(path)

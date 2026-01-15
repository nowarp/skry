"""End-to-end integration tests for Hy rules.

Tests the full pipeline: Move source → parse → facts → HyRule matching → predicate eval → violations.
"""

import textwrap
import tempfile
import os


from core.context import ProjectContext
from analysis import StructuralBuilder
from rules.hy_loader import HyRule, load_hy_rules
from rules.ir import Severity, Binding


class TestEndToEndHyRules:
    """End-to-end tests for Hy rule evaluation."""

    def _create_temp_move_file(self, content: str) -> str:
        """Create a temporary Move file with given content."""
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, "w") as f:
            f.write(textwrap.dedent(content))
        return path

    def _run_hy_rule(self, source: str, rule: HyRule) -> list:
        """Run a single Hy rule against source and return violations."""
        path = self._create_temp_move_file(source)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            file_ctx = ctx.source_files[path]
            facts = file_ctx.facts

            # Find bindings based on match pattern
            bindings = self._find_bindings(rule, facts)

            if not bindings:
                return []

            violations = []

            # Create eval context for predicate
            from rules.eval_context import EvalContext

            eval_ctx = EvalContext(
                ctx=ctx,
                current_file=path,
                current_source=file_ctx.source_code,
                current_root=file_ctx.root,
            )

            for binding in bindings:
                bound_value = binding.get("f") or binding.get("r") or binding.get("e")
                try:
                    # Filter clause check
                    if rule.filter_clause and not rule.filter_clause(bound_value, facts, eval_ctx):
                        continue
                    # Classify clause check (if present)
                    if rule.classify_clause:
                        if rule.classify_clause(bound_value, facts, eval_ctx):
                            violations.append(binding)
                    else:
                        # Filter-only rule
                        violations.append(binding)
                except Exception:
                    # Skip bindings that cause errors (e.g., missing facts)
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

                # Check modifiers
                if "public" in modifiers:
                    if not any(
                        f.name == "IsPublic" and f.args[0] == func_name for f in facts
                    ):
                        continue
                if "entry" in modifiers:
                    if not any(
                        f.name == "IsEntry" and f.args[0] == func_name for f in facts
                    ):
                        continue

                bindings.append(Binding({binding_name: func_name}))

        elif pattern == "capability":
            caps = get_caps(facts)
            for cap_name in caps:
                bindings.append(Binding({binding_name: cap_name}))

        elif pattern == "event":
            events = get_events(facts)
            for event_name in events:
                bindings.append(Binding({binding_name: event_name}))

        elif pattern == "const":
            for fact in facts:
                if fact.name == "ConstDef":
                    const_name = fact.args[0]
                    bindings.append(Binding({binding_name: const_name}))

        return bindings

    def _make_rule(
        self,
        name: str,
        predicate,
        match_pattern: str = "fun",
        match_modifiers: list = None,
        severity: Severity = Severity.HIGH,
    ) -> HyRule:
        """Create a HyRule for testing."""
        return HyRule(
            name=name,
            severity=severity,
            match_pattern=match_pattern,
            match_modifiers=match_modifiers or [],
            match_binding="f",
            filter_clause=predicate,
        )

    # =========================================================================
    # Basic Pattern Matching Tests
    # =========================================================================

    def test_match_public_entry_function(self):
        """Rule with [:public :entry] only matches public entry functions."""
        source = """
            module test::example {
                public entry fun vulnerable(x: u64) {
                    do_something(x);
                }
                public fun not_entry(x: u64) {
                    do_something(x);
                }
                entry fun not_public(x: u64) {
                    do_something(x);
                }
                fun private_func(x: u64) {
                    do_something(x);
                }
            }
        """

        # Simple predicate that always returns True
        rule = self._make_rule(
            name="test_rule",
            predicate=lambda f, facts, ctx: True,
            match_pattern="fun",
            match_modifiers=["public", "entry"],
        )

        violations = self._run_hy_rule(source, rule)

        # Only one public entry function
        assert len(violations) == 1
        assert "vulnerable" in violations[0]["f"]

    def test_match_any_function(self):
        """Rule with no modifiers matches all functions."""
        source = """
            module test::example {
                public entry fun func1(x: u64) {}
                public fun func2(x: u64) {}
                fun func3(x: u64) {}
            }
        """

        rule = self._make_rule(
            name="test_rule",
            predicate=lambda f, facts, ctx: True,
            match_pattern="fun",
            match_modifiers=[],
        )

        violations = self._run_hy_rule(source, rule)

        assert len(violations) == 3
        func_names = {v["f"] for v in violations}
        assert any("func1" in f for f in func_names)
        assert any("func2" in f for f in func_names)
        assert any("func3" in f for f in func_names)

    # =========================================================================
    # Predicate Logic Tests
    # =========================================================================

    def test_predicate_and_logic(self):
        """Predicate with AND logic - both conditions must be true."""
        source = """
            module test::example {
                public entry fun has_both(x: u64) {
                    transfer::public_transfer(x, @0x1);
                }
                public entry fun has_transfer_only(x: u64) {
                    transfer::public_transfer(x, @0x1);
                }
            }
        """

        # Predicate: has transfer AND function name contains "both"
        def predicate(f, facts, ctx):
            has_transfer = any(
                fact.name == "Transfers" and fact.args[0] == f and fact.args[1] is True
                for fact in facts
            )
            name_has_both = "both" in f
            return has_transfer and name_has_both

        rule = self._make_rule(
            name="test_and",
            predicate=predicate,
            match_modifiers=["public", "entry"],
        )

        violations = self._run_hy_rule(source, rule)

        assert len(violations) == 1
        assert "has_both" in violations[0]["f"]

    def test_predicate_or_logic(self):
        """Predicate with OR logic - either condition can be true."""
        source = """
            module test::example {
                public entry fun has_transfer(x: u64) {
                    transfer::public_transfer(x, @0x1);
                }
                public entry fun is_init(ctx: &mut TxContext) {
                    // init-like function
                }
                public entry fun neither(x: u64) {
                    do_something(x);
                }
            }
        """

        # Predicate: has transfer OR name is "init"
        def predicate(f, facts, ctx):
            has_transfer = any(
                fact.name == "Transfers" and fact.args[0] == f and fact.args[1] is True
                for fact in facts
            )
            is_init = f.endswith("::init")
            return has_transfer or is_init

        rule = self._make_rule(
            name="test_or",
            predicate=predicate,
            match_modifiers=["public", "entry"],
        )

        violations = self._run_hy_rule(source, rule)

        # has_transfer matches, neither doesn't, is_init would match but name isn't "init"
        assert len(violations) == 1
        assert "has_transfer" in violations[0]["f"]

    def test_predicate_negation(self):
        """Predicate with NOT logic."""
        source = """
            module test::example {
                public entry fun no_transfer(x: u64) {
                    do_something(x);
                }
                public entry fun has_transfer(x: u64) {
                    transfer::public_transfer(x, @0x1);
                }
            }
        """

        # Predicate: does NOT have transfer
        def predicate(f, facts, ctx):
            has_transfer = any(
                fact.name == "Transfers" and fact.args[0] == f and fact.args[1] is True
                for fact in facts
            )
            return not has_transfer

        rule = self._make_rule(
            name="test_not",
            predicate=predicate,
            match_modifiers=["public", "entry"],
        )

        violations = self._run_hy_rule(source, rule)

        assert len(violations) == 1
        assert "no_transfer" in violations[0]["f"]

    # =========================================================================
    # Structural Check Tests
    # =========================================================================

    def test_checks_role_detection(self):
        """Detect function based on formal argument types."""
        source = """
            module test::example {
                struct AdminCap has key, store {
                    id: UID
                }

                public entry fun admin_only(_: &AdminCap, x: u64) {
                    do_admin_stuff(x);
                }

                public entry fun no_cap(x: u64) {
                    do_stuff(x);
                }
            }
        """

        # Predicate: function has a Cap-typed argument (simplified check)
        def predicate(f, facts, ctx):
            has_cap_arg = any(
                fact.name == "FormalArg"
                and fact.args[0] == f
                and "Cap" in fact.args[3]
                for fact in facts
            )
            return has_cap_arg

        rule = self._make_rule(
            name="has_cap_arg",
            predicate=predicate,
            match_modifiers=["public", "entry"],
        )

        violations = self._run_hy_rule(source, rule)

        # Only admin_only has Cap argument
        assert len(violations) == 1
        assert "admin_only" in violations[0]["f"]

    def test_transfer_detection(self):
        """Detect function that performs transfers."""
        source = """
            module test::example {
                public entry fun does_transfer(coin: Coin<SUI>, recipient: address) {
                    transfer::public_transfer(coin, recipient);
                }

                public entry fun no_transfer(x: u64) {
                    compute(x);
                }
            }
        """

        # Predicate: function performs transfer
        def predicate(f, facts, ctx):
            return any(
                fact.name == "Transfers" and fact.args[0] == f and fact.args[1] is True
                for fact in facts
            )

        rule = self._make_rule(
            name="has_transfer",
            predicate=predicate,
            match_modifiers=["public", "entry"],
        )

        violations = self._run_hy_rule(source, rule)

        assert len(violations) == 1
        assert "does_transfer" in violations[0]["f"]

    # =========================================================================
    # Capability/Event Pattern Tests
    # =========================================================================

    def test_capability_pattern_matching(self):
        """Rule with :capability pattern matches capability structs."""
        source = """
            module test::example {
                struct AdminCap has key, store {
                    id: UID
                }

                struct OwnerCap has key {
                    id: UID
                }

                struct NotACap has key {
                    id: UID,
                    value: u64
                }

                fun init(ctx: &mut TxContext) {
                    let admin = AdminCap { id: object::new(ctx) };
                    let owner = OwnerCap { id: object::new(ctx) };
                    transfer::transfer(admin, tx_context::sender(ctx));
                    transfer::transfer(owner, tx_context::sender(ctx));
                }
            }
        """

        rule = HyRule(
            name="test_capability",
            severity=Severity.MEDIUM,
            match_pattern="capability",
            match_modifiers=[],
            match_binding="f",
            filter_clause=lambda f, facts, ctx: True,  # Match all capabilities
        )

        violations = self._run_hy_rule(source, rule)

        # Should match AdminCap and OwnerCap (both are Cap structs with UID)
        cap_names = {v["f"] for v in violations}
        assert any("AdminCap" in r for r in cap_names)
        assert any("OwnerCap" in r for r in cap_names)

    def test_event_pattern_matching(self):
        """Rule with :event pattern matches event structs."""
        source = """
            module test::example {
                struct TransferEvent has copy, drop {
                    from: address,
                    to: address,
                    amount: u64
                }

                struct DepositEvent has copy, drop {
                    user: address,
                    amount: u64
                }

                struct NotAnEvent has key {
                    id: UID
                }
            }
        """

        rule = HyRule(
            name="test_event",
            severity=Severity.MEDIUM,
            match_pattern="event",
            match_modifiers=[],
            match_binding="f",
            filter_clause=lambda f, facts, ctx: True,  # Match all events
        )

        violations = self._run_hy_rule(source, rule)

        # Should match TransferEvent and DepositEvent (copy+drop, name ends with Event)
        event_names = {v["f"] for v in violations}
        assert any("TransferEvent" in e for e in event_names)
        assert any("DepositEvent" in e for e in event_names)


class TestLoadedHyRules:
    """Test that actual Hy rule files load and work correctly."""

    def test_load_access_control_rules(self):
        """Load access_control.hy and verify rules are valid."""
        rules = load_hy_rules("rules/access_control.hy")

        assert len(rules) > 0

        for rule in rules:
            assert rule.name, "Rule must have a name"
            assert rule.severity in Severity, "Rule must have valid severity"
            assert rule.match_pattern in [
                "fun",
                "capability",
                "event",
                "const",
                "mutable-config-field",
                "writes-protocol-invariant",
            ], f"Invalid pattern: {rule.match_pattern}"
            assert callable(rule.filter_clause), "Rule must have callable filter_clause"

    def test_load_structural_rules(self):
        """Load structural.hy and verify rules are valid."""
        rules = load_hy_rules("rules/structural.hy")

        assert len(rules) > 0

        # Check some expected rules exist
        rule_names = {r.name for r in rules}
        assert any("double-init" in n or "missing" in n for n in rule_names)

    def test_load_code_quality_rules(self):
        """Load code_quality.hy and verify rules are valid."""
        rules = load_hy_rules("rules/code_quality.hy")

        assert len(rules) > 0

    def test_all_rules_have_filter_clause(self):
        """All loaded rules must have working filter clauses."""
        import glob

        for rule_file in glob.glob("rules/*.hy"):
            rules = load_hy_rules(rule_file)
            for rule in rules:
                # Filter clause should be callable
                assert callable(
                    rule.filter_clause
                ), f"Rule {rule.name} in {rule_file} has non-callable filter_clause"


class TestDoubleInitRule:
    """Tests for the double-init rule - non-init function calling module init."""

    def _create_temp_move_file(self, content: str) -> str:
        """Create a temporary Move file with given content."""
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, "w") as f:
            f.write(textwrap.dedent(content))
        return path

    def _run_double_init_check(self, source: str) -> list:
        """Run double-init rule against source and return violations."""
        rules = load_hy_rules("rules/structural.hy")
        double_init_rule = next((r for r in rules if r.name == "double-init"), None)
        assert double_init_rule is not None, "double-init rule not found"

        path = self._create_temp_move_file(source)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            file_ctx = ctx.source_files[path]
            facts = file_ctx.facts

            from rules.eval_context import EvalContext

            eval_ctx = EvalContext(
                ctx=ctx,
                current_file=path,
                current_source=file_ctx.source_code,
                current_root=file_ctx.root,
            )

            violations = []
            for fact in facts:
                if fact.name == "Fun":
                    func_name = fact.args[0]
                    try:
                        # Evaluate filter clause
                        if double_init_rule.filter_clause and not double_init_rule.filter_clause(func_name, facts, eval_ctx):
                            continue
                        # No classify clause for double-init rule
                        violations.append(func_name)
                    except Exception:
                        pass

            return violations
        finally:
            os.unlink(path)

    def test_no_false_positive_on_new_reader(self):
        """new_reader() calls should NOT trigger double-init."""
        source = """
            module test::discovery {
                use abi::abi::{Self, AbiReader};

                public fun parse_message(payload: vector<u8>): u64 {
                    let mut reader = abi::new_reader(payload);
                    let msg_type = reader.read_u256();
                    reader = abi::new_reader(payload);  // reassignment, not double init
                    (msg_type as u64)
                }
            }
        """
        violations = self._run_double_init_check(source)
        assert len(violations) == 0, f"Unexpected violations: {violations}"

    def test_no_false_positive_on_factory_functions(self):
        """Factory functions like new(), create() should NOT trigger double-init."""
        source = """
            module test::example {
                public fun build_stuff() {
                    let x = foo::new();
                    let y = bar::create();
                    let z = baz::initialize();
                }
            }
        """
        violations = self._run_double_init_check(source)
        assert len(violations) == 0, f"Unexpected violations: {violations}"

    def test_detect_actual_init_call(self):
        """Calling actual module init() from non-init function should be flagged."""
        source = """
            module test::example {
                fun init(ctx: &mut TxContext) {
                    // module init
                }

                public fun reinit(ctx: &mut TxContext) {
                    init(ctx);  // This is the vulnerability!
                }
            }
        """
        violations = self._run_double_init_check(source)
        # reinit should be flagged for calling init
        assert any("reinit" in v for v in violations), f"Expected reinit violation, got: {violations}"

    def test_skip_test_only_functions(self):
        """#[test_only] functions should be skipped."""
        source = """
            module test::example {
                fun init(ctx: &mut TxContext) {
                    // module init
                }

                #[test_only]
                public fun destroy_for_testing() {
                    // test helper that might call init indirectly
                }

                #[test]
                fun test_init() {
                    init(dummy_ctx());  // ok in tests
                }
            }
        """
        violations = self._run_double_init_check(source)
        # test_only and test functions should not be flagged
        assert not any("destroy_for_testing" in v for v in violations)
        assert not any("test_init" in v for v in violations)


class TestFeatureExtraction:
    """Tests for automatic feature extraction from rule clauses."""

    def test_version_feature_extracted(self):
        """Rules using feature-version? should have 'version' in features."""
        rules = load_hy_rules("rules/structural.hy")
        version_rule = next((r for r in rules if r.name == "version-check-missing"), None)
        assert version_rule is not None, "version-check-missing rule not found"
        assert "version" in version_rule.features, f"Expected 'version' in features, got: {version_rule.features}"

    def test_rule_without_features(self):
        """Rules not using feature functions should have empty features."""
        rules = load_hy_rules("rules/structural.hy")
        double_init_rule = next((r for r in rules if r.name == "double-init"), None)
        assert double_init_rule is not None, "double-init rule not found"
        assert len(double_init_rule.features) == 0, f"Expected empty features, got: {double_init_rule.features}"

    def test_collect_required_features(self):
        """collect_required_features should aggregate features from all rules."""
        from rules.utils import collect_required_features

        rules = load_hy_rules("rules/structural.hy")
        features = collect_required_features(rules)

        # At least version-check-missing uses version feature
        assert "version" in features, f"Expected 'version' in collected features, got: {features}"

    def test_feature_fact_names_mapping(self):
        """FEATURE_FACT_NAMES should map features to their fact names."""
        from features.runner import FEATURE_FACT_NAMES

        assert "version" in FEATURE_FACT_NAMES
        assert "FeatureVersion" in FEATURE_FACT_NAMES["version"]
        assert "category" in FEATURE_FACT_NAMES
        assert "ProjectCategory" in FEATURE_FACT_NAMES["category"]

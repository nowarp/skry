"""Tests for field-based check derivation (ChecksLock, ChecksPause, etc.)."""
import textwrap
import tempfile
import os

from core.context import ProjectContext
from core.facts import Fact
from analysis import run_structural_analysis
from analysis.field_checks import derive_field_check_facts, find_functions_checking_field
from test_utils import has_fact, get_facts


class TestFindFunctionsCheckingField:
    """Test find_functions_checking_field - strict struct.field matching."""

    def _create_temp_move_file(self, content: str) -> str:
        """Create a temporary Move file and return its path."""
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, 'w') as f:
            f.write(textwrap.dedent(content))
        return path

    def test_direct_condition_field_access(self):
        """Function checking field directly in condition."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct Config has key {
                    paused: bool
                }

                public fun withdraw(config: &Config) {
                    assert!(!config.paused, E_PAUSED);
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)

            # Add ConditionFieldAccess fact manually (normally from collectors)
            file_ctx = ctx.source_files[path]
            file_ctx.facts.append(
                Fact("ConditionFieldAccess", ("test::pool::withdraw", "1", "config.paused", "paused"))
            )
            file_ctx.facts.append(
                Fact("FieldAccess", ("test::pool::withdraw", "test::pool::Config", "paused", "config.paused", "1"))
            )

            result = find_functions_checking_field(ctx, "test::pool::Config", "paused")
            assert "test::pool::withdraw" in result
        finally:
            os.unlink(path)

    def test_indirect_condition_via_variable(self):
        """Function reads field to variable, then checks variable in condition."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct Config has key {
                    paused: bool
                }

                public fun withdraw(config: &Config) {
                    let is_paused = config.paused;
                    assert!(!is_paused, E_PAUSED);
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)

            file_ctx = ctx.source_files[path]
            # FieldAssign: function reads field to variable
            file_ctx.facts.append(
                Fact("FieldAssign", ("test::pool::withdraw", "1", "is_paused", "config.paused", "paused"))
            )
            # ConditionCheck: variable used in condition
            file_ctx.facts.append(
                Fact("ConditionCheck", ("test::pool::withdraw", "2", ["is_paused"]))
            )
            # FieldAccess to match struct type
            file_ctx.facts.append(
                Fact("FieldAccess", ("test::pool::withdraw", "test::pool::Config", "paused", "config.paused", "1"))
            )

            result = find_functions_checking_field(ctx, "test::pool::Config", "paused")
            assert "test::pool::withdraw" in result
        finally:
            os.unlink(path)

    def test_variable_propagation_through_assignments(self):
        """Field value propagates through multiple variable assignments."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct Config has key {
                    paused: bool
                }

                public fun withdraw(config: &Config) {
                    let is_paused = config.paused;
                    let flag = is_paused;
                    assert!(!flag, E_PAUSED);
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)

            file_ctx = ctx.source_files[path]
            file_ctx.facts.append(
                Fact("FieldAssign", ("test::pool::withdraw", "1", "is_paused", "config.paused", "paused"))
            )
            file_ctx.facts.append(
                Fact("Assigns", ("test::pool::withdraw", "2", "flag", ["is_paused"]))
            )
            file_ctx.facts.append(
                Fact("ConditionCheck", ("test::pool::withdraw", "3", ["flag"]))
            )
            file_ctx.facts.append(
                Fact("FieldAccess", ("test::pool::withdraw", "test::pool::Config", "paused", "config.paused", "1"))
            )

            result = find_functions_checking_field(ctx, "test::pool::Config", "paused")
            assert "test::pool::withdraw" in result
        finally:
            os.unlink(path)

    def test_no_false_positive_different_struct_same_field(self):
        """Should not match if struct type differs (even with same field name)."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct ConfigA has key { paused: bool }
                struct ConfigB has key { paused: bool }

                public fun check_a(a: &ConfigA) {
                    assert!(!a.paused, E_PAUSED);
                }

                public fun check_b(b: &ConfigB) {
                    assert!(!b.paused, E_PAUSED);
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)

            file_ctx = ctx.source_files[path]
            # check_a accesses ConfigA.paused
            file_ctx.facts.append(
                Fact("ConditionFieldAccess", ("test::pool::check_a", "1", "a.paused", "paused"))
            )
            file_ctx.facts.append(
                Fact("FieldAccess", ("test::pool::check_a", "test::pool::ConfigA", "paused", "a.paused", "1"))
            )
            # check_b accesses ConfigB.paused
            file_ctx.facts.append(
                Fact("ConditionFieldAccess", ("test::pool::check_b", "1", "b.paused", "paused"))
            )
            file_ctx.facts.append(
                Fact("FieldAccess", ("test::pool::check_b", "test::pool::ConfigB", "paused", "b.paused", "1"))
            )

            # Query ConfigA.paused - should only match check_a
            result_a = find_functions_checking_field(ctx, "test::pool::ConfigA", "paused")
            assert "test::pool::check_a" in result_a
            assert "test::pool::check_b" not in result_a

            # Query ConfigB.paused - should only match check_b
            result_b = find_functions_checking_field(ctx, "test::pool::ConfigB", "paused")
            assert "test::pool::check_b" in result_b
            assert "test::pool::check_a" not in result_b
        finally:
            os.unlink(path)

    def test_no_match_when_field_not_in_condition(self):
        """Function accesses field but doesn't use it in condition."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct Config has key {
                    paused: bool,
                    fee_rate: u64
                }

                public fun get_fee(config: &Config): u64 {
                    let is_paused = config.paused;
                    config.fee_rate  // Returns fee, doesn't check paused
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)

            file_ctx = ctx.source_files[path]
            # Field accessed but not used in condition
            file_ctx.facts.append(
                Fact("FieldAssign", ("test::pool::get_fee", "1", "is_paused", "config.paused", "paused"))
            )
            file_ctx.facts.append(
                Fact("FieldAccess", ("test::pool::get_fee", "test::pool::Config", "paused", "config.paused", "1"))
            )
            # No ConditionCheck with is_paused

            result = find_functions_checking_field(ctx, "test::pool::Config", "paused")
            assert "test::pool::get_fee" not in result
        finally:
            os.unlink(path)

    def test_simple_name_matching_cross_module(self):
        """Should match both FQN and simple name for cross-module usage."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct Config has key {
                    paused: bool
                }

                public fun check_paused(config: &Config) {
                    assert!(!config.paused, E_PAUSED);
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)

            file_ctx = ctx.source_files[path]
            # Simulating cross-module: FieldAccess uses simple name
            file_ctx.facts.append(
                Fact("ConditionFieldAccess", ("test::pool::check_paused", "1", "config.paused", "paused"))
            )
            file_ctx.facts.append(
                Fact("FieldAccess", ("test::pool::check_paused", "Config", "paused", "config.paused", "1"))
            )

            # Query with FQN should still match simple name
            result = find_functions_checking_field(ctx, "test::pool::Config", "paused")
            assert "test::pool::check_paused" in result
        finally:
            os.unlink(path)


class TestDeriveFieldCheckFacts:
    """Test derive_field_check_facts - generic check derivation from classified fields."""

    def _create_temp_move_file(self, content: str) -> str:
        """Create a temporary Move file and return its path."""
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, 'w') as f:
            f.write(textwrap.dedent(content))
        return path

    def test_direct_condition_field_access_generates_check(self):
        """Direct field check in condition generates ChecksFact."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct Config has key { paused: bool }

                public fun withdraw(config: &Config) {
                    assert!(!config.paused, E_PAUSED);
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)

            file_ctx = ctx.source_files[path]
            # Classify field as lock field
            file_ctx.facts.append(Fact("FieldClassification", ("test::pool::Config", "paused", "lock", False, 1.0, "")))
            # Add ReadsField fact
            file_ctx.facts.append(Fact("ReadsField", ("test::pool::withdraw", "test::pool::Config", "paused")))
            # Condition accesses this field
            file_ctx.facts.append(Fact("ConditionFieldAccess", ("test::pool::withdraw", "1", "config.paused", "paused")))

            count = derive_field_check_facts(ctx, "lock", "ChecksLock", None, "lock_test")
            assert count == 1
            assert has_fact(file_ctx.facts, "ChecksLock", ("test::pool::withdraw",))
        finally:
            os.unlink(path)

    def test_indirect_check_via_variable_generates_check(self):
        """Field read to variable, variable checked in condition."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct Config has key { paused: bool }

                public fun withdraw(config: &Config) {
                    let is_paused = config.paused;
                    assert!(!is_paused, E_PAUSED);
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)

            file_ctx = ctx.source_files[path]
            file_ctx.facts.append(Fact("FieldClassification", ("test::pool::Config", "paused", "lock", False, 1.0, "")))
            file_ctx.facts.append(Fact("ReadsField", ("test::pool::withdraw", "test::pool::Config", "paused")))
            file_ctx.facts.append(Fact("FieldAssign", ("test::pool::withdraw", "1", "is_paused", "config.paused", "paused")))
            file_ctx.facts.append(Fact("ConditionCheck", ("test::pool::withdraw", "2", ["is_paused"])))

            count = derive_field_check_facts(ctx, "lock", "ChecksLock", None, "lock_test")
            assert count == 1
            assert has_fact(file_ctx.facts, "ChecksLock", ("test::pool::withdraw",))
        finally:
            os.unlink(path)

    def test_transitive_propagation_via_assigns(self):
        """Field value propagates through multiple assignments before condition."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct Config has key { paused: bool }

                public fun withdraw(config: &Config) {
                    let temp1 = config.paused;
                    let temp2 = temp1;
                    let flag = temp2;
                    assert!(!flag, E_PAUSED);
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)

            file_ctx = ctx.source_files[path]
            file_ctx.facts.append(Fact("FieldClassification", ("test::pool::Config", "paused", "lock", False, 1.0, "")))
            file_ctx.facts.append(Fact("ReadsField", ("test::pool::withdraw", "test::pool::Config", "paused")))
            file_ctx.facts.append(Fact("FieldAssign", ("test::pool::withdraw", "1", "temp1", "config.paused", "paused")))
            file_ctx.facts.append(Fact("Assigns", ("test::pool::withdraw", "2", "temp2", ["temp1"])))
            file_ctx.facts.append(Fact("Assigns", ("test::pool::withdraw", "3", "flag", ["temp2"])))
            file_ctx.facts.append(Fact("ConditionCheck", ("test::pool::withdraw", "4", ["flag"])))

            count = derive_field_check_facts(ctx, "lock", "ChecksLock", None, "lock_test")
            assert count == 1
            assert has_fact(file_ctx.facts, "ChecksLock", ("test::pool::withdraw",))
        finally:
            os.unlink(path)

    def test_interprocedural_return_value_tracking(self):
        """Function returns field value, caller checks it."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct Config has key { paused: bool }

                public fun is_paused(config: &Config): bool {
                    config.paused
                }

                public fun withdraw(config: &Config) {
                    let paused = is_paused(config);
                    assert!(!paused, E_PAUSED);
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)

            file_ctx = ctx.source_files[path]
            file_ctx.facts.append(Fact("FieldClassification", ("test::pool::Config", "paused", "lock", False, 1.0, "")))
            # is_paused reads field
            file_ctx.facts.append(Fact("ReadsField", ("test::pool::is_paused", "test::pool::Config", "paused")))
            file_ctx.facts.append(Fact("ReturnsFieldValue", ("test::pool::is_paused", "paused")))
            # withdraw calls is_paused
            file_ctx.facts.append(Fact("CallResult", ("test::pool::withdraw", "1", "paused", "test::pool::is_paused")))
            file_ctx.facts.append(Fact("ConditionCheck", ("test::pool::withdraw", "2", ["paused"])))

            count = derive_field_check_facts(ctx, "lock", "ChecksLock", None, "lock_test")
            # Only withdraw should get ChecksLock (it checks the return value)
            # is_paused only returns the field value but doesn't check it in a condition
            assert count == 1
            assert has_fact(file_ctx.facts, "ChecksLock", ("test::pool::withdraw",))
        finally:
            os.unlink(path)

    def test_interprocedural_argument_passing(self):
        """Field value passed as argument to helper that checks it."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct Config has key { paused: bool }

                fun assert_not_paused(flag: bool) {
                    assert!(!flag, E_PAUSED);
                }

                public fun withdraw(config: &Config) {
                    assert_not_paused(config.paused);
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)

            file_ctx = ctx.source_files[path]
            file_ctx.facts.append(Fact("FieldClassification", ("test::pool::Config", "paused", "lock", False, 1.0, "")))
            # withdraw reads field
            file_ctx.facts.append(Fact("ReadsField", ("test::pool::withdraw", "test::pool::Config", "paused")))
            # Field assigned to variable
            file_ctx.facts.append(Fact("FieldAssign", ("test::pool::withdraw", "1", "tmp_paused", "config.paused", "paused")))
            # Variable passed to helper
            file_ctx.facts.append(Fact("CallArg", ("test::pool::withdraw", "2", "test::pool::assert_not_paused", 0, ["tmp_paused"])))
            file_ctx.facts.append(Fact("FormalArg", ("test::pool::assert_not_paused", 0, "flag", "bool")))
            # Helper checks parameter
            file_ctx.facts.append(Fact("ConditionCheck", ("test::pool::assert_not_paused", "1", ["flag"])))

            count = derive_field_check_facts(ctx, "lock", "ChecksLock", None, "lock_test")
            # Both functions should get ChecksLock
            assert count >= 1
            # withdraw directly checks (via reading field and using in condition flow)
            checks = get_facts(file_ctx.facts, "ChecksLock")
            func_names = {f.args[0] for f in checks}
            assert "test::pool::assert_not_paused" in func_names
        finally:
            os.unlink(path)

    def test_multiple_classified_fields(self):
        """Multiple classified fields in same struct."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct Config has key {
                    paused: bool,
                    frozen: bool
                }

                public fun check_paused(config: &Config) {
                    assert!(!config.paused, E_PAUSED);
                }

                public fun check_frozen(config: &Config) {
                    assert!(!config.frozen, E_FROZEN);
                }

                public fun check_both(config: &Config) {
                    assert!(!config.paused, E_PAUSED);
                    assert!(!config.frozen, E_FROZEN);
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)

            file_ctx = ctx.source_files[path]
            # Classify both fields
            file_ctx.facts.append(Fact("FieldClassification", ("test::pool::Config", "paused", "lock", False, 1.0, "")))
            file_ctx.facts.append(Fact("FieldClassification", ("test::pool::Config", "frozen", "lock", False, 1.0, "")))
            # ReadsField
            file_ctx.facts.append(Fact("ReadsField", ("test::pool::check_paused", "test::pool::Config", "paused")))
            file_ctx.facts.append(Fact("ReadsField", ("test::pool::check_frozen", "test::pool::Config", "frozen")))
            file_ctx.facts.append(Fact("ReadsField", ("test::pool::check_both", "test::pool::Config", "paused")))
            file_ctx.facts.append(Fact("ReadsField", ("test::pool::check_both", "test::pool::Config", "frozen")))
            # Conditions
            file_ctx.facts.append(Fact("ConditionFieldAccess", ("test::pool::check_paused", "1", "config.paused", "paused")))
            file_ctx.facts.append(Fact("ConditionFieldAccess", ("test::pool::check_frozen", "1", "config.frozen", "frozen")))
            file_ctx.facts.append(Fact("ConditionFieldAccess", ("test::pool::check_both", "1", "config.paused", "paused")))
            file_ctx.facts.append(Fact("ConditionFieldAccess", ("test::pool::check_both", "2", "config.frozen", "frozen")))

            count = derive_field_check_facts(ctx, "lock", "ChecksLock", None, "lock_test")
            assert count == 3  # All three functions check at least one classified field
            assert has_fact(file_ctx.facts, "ChecksLock", ("test::pool::check_paused",))
            assert has_fact(file_ctx.facts, "ChecksLock", ("test::pool::check_frozen",))
            assert has_fact(file_ctx.facts, "ChecksLock", ("test::pool::check_both",))
        finally:
            os.unlink(path)

    def test_nested_field_path_matching(self):
        """Nested field path (config.settings.paused) should match classified field."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct Settings has store { paused: bool }
                struct Config has key { settings: Settings }

                public fun withdraw(config: &Config) {
                    assert!(!config.settings.paused, E_PAUSED);
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)

            file_ctx = ctx.source_files[path]
            # Classify nested field
            file_ctx.facts.append(Fact("FieldClassification", ("test::pool::Config", "settings.paused", "lock", False, 1.0, "")))
            # ReadsField for nested path
            file_ctx.facts.append(Fact("ReadsField", ("test::pool::withdraw", "test::pool::Config", "settings.paused")))
            # Condition accesses nested field
            file_ctx.facts.append(Fact("ConditionFieldAccess", ("test::pool::withdraw", "1", "config.settings.paused", "settings.paused")))

            count = derive_field_check_facts(ctx, "lock", "ChecksLock", None, "lock_test")
            assert count == 1
            assert has_fact(file_ctx.facts, "ChecksLock", ("test::pool::withdraw",))
        finally:
            os.unlink(path)

    def test_infrastructure_fact_generation(self):
        """If classified fields exist, infrastructure fact should be generated."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct Config has key { paused: bool }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)

            file_ctx = ctx.source_files[path]
            file_ctx.facts.append(Fact("FieldClassification", ("test::pool::Config", "paused", "lock", False, 1.0, "")))

            _ = derive_field_check_facts(
                ctx,
                "lock",
                "ChecksLock",
                infrastructure_fact_name="HasLockInfrastructure",
                debug_prefix="lock_test"
            )

            # Infrastructure fact should be in project facts
            assert has_fact(ctx.project_facts, "HasLockInfrastructure", (True,))
        finally:
            os.unlink(path)

    def test_no_classified_fields_no_facts(self):
        """If no classified fields, no check facts generated."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct Config has key { paused: bool }

                public fun withdraw(config: &Config) {
                    assert!(!config.paused, E_PAUSED);
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)

            file_ctx = ctx.source_files[path]
            # No IsLockField facts
            file_ctx.facts.append(Fact("ConditionFieldAccess", ("test::pool::withdraw", "1", "config.paused", "paused")))

            count = derive_field_check_facts(ctx, "lock", "ChecksLock", None, "lock_test")
            assert count == 0
            checks = get_facts(file_ctx.facts, "ChecksLock")
            assert len(checks) == 0
        finally:
            os.unlink(path)

    def test_no_duplicate_check_facts(self):
        """Should not generate duplicate ChecksLock facts for same function."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct Config has key { paused: bool }

                public fun withdraw(config: &Config) {
                    assert!(!config.paused, E_PAUSED);
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)

            file_ctx = ctx.source_files[path]
            file_ctx.facts.append(Fact("FieldClassification", ("test::pool::Config", "paused", "lock", False, 1.0, "")))
            file_ctx.facts.append(Fact("ReadsField", ("test::pool::withdraw", "test::pool::Config", "paused")))
            file_ctx.facts.append(Fact("ConditionFieldAccess", ("test::pool::withdraw", "1", "config.paused", "paused")))

            # Run twice
            count1 = derive_field_check_facts(ctx, "lock", "ChecksLock", None, "lock_test")
            count2 = derive_field_check_facts(ctx, "lock", "ChecksLock", None, "lock_test")

            assert count1 == 1
            assert count2 == 0  # No new facts on second run
            checks = get_facts(file_ctx.facts, "ChecksLock")
            assert len(checks) == 1  # Only one fact
        finally:
            os.unlink(path)

    def test_simple_name_cross_module_matching(self):
        """Should match both FQN and simple name for cross-module field access."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct Config has key { paused: bool }

                public fun withdraw(config: &Config) {
                    assert!(!config.paused, E_PAUSED);
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)

            file_ctx = ctx.source_files[path]
            # Classify with FQN
            file_ctx.facts.append(Fact("FieldClassification", ("test::pool::Config", "paused", "lock", False, 1.0, "")))
            # ReadsField with simple name (simulating cross-module import)
            file_ctx.facts.append(Fact("ReadsField", ("test::pool::withdraw", "Config", "paused")))
            file_ctx.facts.append(Fact("ConditionFieldAccess", ("test::pool::withdraw", "1", "config.paused", "paused")))

            count = derive_field_check_facts(ctx, "lock", "ChecksLock", None, "lock_test")
            assert count == 1
            assert has_fact(file_ctx.facts, "ChecksLock", ("test::pool::withdraw",))
        finally:
            os.unlink(path)

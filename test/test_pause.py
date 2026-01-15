"""Tests for pause check propagation.

Tests the compute_pause_facts() which uses IsGlobalPauseField from PauseDetector
to propagate ChecksPause through the call graph.
"""

import pytest

from core.facts import Fact
from core.context import ProjectContext
from analysis.pause import compute_pause_facts
from test_utils import has_fact


class TestNoPauseConfig:
    """Test behavior when no IsGlobalPauseField is set."""

    def test_no_pause_config_no_propagation(self):
        """Without IsGlobalPauseField, no ChecksPause should be generated."""
        ctx = ProjectContext(["file.move"])
        ctx.source_files["file.move"].facts = [
            Fact("Fun", ("test::deposit",)),
            Fact("ConditionFieldAccess", ("test::deposit", "stmt_1", "config", "paused")),
        ]
        ctx.project_facts = []  # No IsGlobalPauseField

        compute_pause_facts(ctx)

        assert not has_fact(ctx.source_files["file.move"].facts, "ChecksPause", ("test::deposit",))

    def test_feature_pause_false_no_propagation(self):
        """With FeaturePause(False), no ChecksPause should be generated."""
        ctx = ProjectContext(["file.move"])
        ctx.source_files["file.move"].facts = [
            Fact("Fun", ("test::deposit",)),
            Fact("ConditionFieldAccess", ("test::deposit", "stmt_1", "config", "paused")),
        ]
        ctx.project_facts = [Fact("FeaturePause", (False,))]

        compute_pause_facts(ctx)

        assert not has_fact(ctx.source_files["file.move"].facts, "ChecksPause", ("test::deposit",))


class TestChecksPauseDirectCondition:
    """Test ChecksPause with direct field access in condition."""

    def test_direct_condition_field_access(self):
        """Direct field access in condition: if (config.paused) -> ChecksPause."""
        ctx = ProjectContext(["file.move"])
        ctx.source_files["file.move"].facts = [
            Fact("Fun", ("test::deposit",)),
            Fact("FieldAccess", ("test::deposit", "test::Config", "paused", "config.paused", 10)),
            Fact("ConditionFieldAccess", ("test::deposit", "stmt_1", "config", "paused")),
            Fact("ConditionCheck", ("test::deposit", "stmt_1", ("config",))),
        ]
        ctx.project_facts = [
            Fact("FeaturePause", (True,)),
            Fact("IsGlobalPauseField", ("test::Config", "paused")),
        ]

        compute_pause_facts(ctx)

        assert has_fact(ctx.source_files["file.move"].facts, "ChecksPause", ("test::deposit",))

    def test_condition_field_access_simple_name(self):
        """ConditionFieldAccess with simple struct name matches FQN in IsGlobalPauseField."""
        ctx = ProjectContext(["file.move"])
        ctx.source_files["file.move"].facts = [
            Fact("Fun", ("test::deposit",)),
            # FieldAccess required for struct type verification
            Fact("FieldAccess", ("test::deposit", "test::Config", "paused", "config.paused", 10)),
            Fact("ConditionFieldAccess", ("test::deposit", "stmt_1", "config", "paused")),
        ]
        ctx.project_facts = [
            Fact("FeaturePause", (True,)),
            Fact("IsGlobalPauseField", ("test::Config", "paused")),  # FQN
        ]

        compute_pause_facts(ctx)

        # Should match via simple name extraction
        assert has_fact(ctx.source_files["file.move"].facts, "ChecksPause", ("test::deposit",))


class TestChecksPauseIndirectCondition:
    """Test ChecksPause with indirect field access (via variable)."""

    def test_field_assign_to_variable(self):
        """Field value assigned to variable used in condition."""
        ctx = ProjectContext(["file.move"])
        ctx.source_files["file.move"].facts = [
            Fact("Fun", ("test::deposit",)),
            Fact("FieldAccess", ("test::deposit", "test::Config", "paused", "config.paused", 10)),
            # let is_paused = config.paused
            Fact("FieldAssign", ("test::deposit", "stmt_1", "is_paused", "config", "paused")),
            Fact("Assigns", ("test::deposit", "stmt_1", "is_paused", ("config",))),
            # if (is_paused)
            Fact("ConditionCheck", ("test::deposit", "stmt_2", ("is_paused",))),
        ]
        ctx.project_facts = [
            Fact("FeaturePause", (True,)),
            Fact("IsGlobalPauseField", ("test::Config", "paused")),
        ]

        compute_pause_facts(ctx)

        assert has_fact(ctx.source_files["file.move"].facts, "ChecksPause", ("test::deposit",))

    def test_transitive_assignment(self):
        """Transitive assignment: let x = config.paused; let y = x; if (y)."""
        ctx = ProjectContext(["file.move"])
        ctx.source_files["file.move"].facts = [
            Fact("Fun", ("test::deposit",)),
            Fact("FieldAccess", ("test::deposit", "test::Config", "paused", "config.paused", 10)),
            # let x = config.paused
            Fact("FieldAssign", ("test::deposit", "stmt_1", "x", "config", "paused")),
            Fact("Assigns", ("test::deposit", "stmt_1", "x", ("config",))),
            # let y = x
            Fact("Assigns", ("test::deposit", "stmt_2", "y", ("x",))),
            # if (y)
            Fact("ConditionCheck", ("test::deposit", "stmt_3", ("y",))),
        ]
        ctx.project_facts = [
            Fact("FeaturePause", (True,)),
            Fact("IsGlobalPauseField", ("test::Config", "paused")),
        ]

        compute_pause_facts(ctx)

        assert has_fact(ctx.source_files["file.move"].facts, "ChecksPause", ("test::deposit",))


class TestChecksPauseNoFalsePositive:
    """Test that unrelated conditions don't trigger ChecksPause."""

    def test_unrelated_condition_no_check(self):
        """Condition on unrelated variable -> no ChecksPause."""
        ctx = ProjectContext(["file.move"])
        ctx.source_files["file.move"].facts = [
            Fact("Fun", ("test::deposit",)),
            Fact("FieldAccess", ("test::deposit", "test::Config", "paused", "config.paused", 10)),
            # Condition is on 'amount', not pause value
            Fact("ConditionCheck", ("test::deposit", "stmt_2", ("amount",))),
        ]
        ctx.project_facts = [
            Fact("FeaturePause", (True,)),
            Fact("IsGlobalPauseField", ("test::Config", "paused")),
        ]

        compute_pause_facts(ctx)

        assert not has_fact(ctx.source_files["file.move"].facts, "ChecksPause", ("test::deposit",))

    def test_field_access_different_field_in_condition(self):
        """Condition checks different field than pause field."""
        ctx = ProjectContext(["file.move"])
        ctx.source_files["file.move"].facts = [
            Fact("Fun", ("test::deposit",)),
            # Condition checks 'enabled' field, not 'paused'
            Fact("ConditionFieldAccess", ("test::deposit", "stmt_1", "config", "enabled")),
            Fact("ConditionCheck", ("test::deposit", "stmt_1", ("config",))),
        ]
        ctx.project_facts = [
            Fact("FeaturePause", (True,)),
            Fact("IsGlobalPauseField", ("test::Config", "paused")),
        ]

        compute_pause_facts(ctx)

        assert not has_fact(ctx.source_files["file.move"].facts, "ChecksPause", ("test::deposit",))


class TestAssertConditionTracking:
    """Tests for assert! condition tracking."""

    def test_assert_direct_field_access(self):
        """Direct field access in assert! triggers ChecksPause."""
        ctx = ProjectContext(["file.move"])
        ctx.source_files["file.move"].facts = [
            Fact("Struct", ("test::Config",)),
            Fact("Fun", ("test::deposit",)),
            Fact("FieldAccess", ("test::deposit", "test::Config", "paused", "config.paused", 5)),
            # Generated from assert!(!config.paused, E_PAUSED)
            Fact("ConditionFieldAccess", ("test::deposit", "stmt_1", "config", "paused")),
            Fact("ConditionCheck", ("test::deposit", "stmt_1", ("config",))),
        ]
        ctx.project_facts = [
            Fact("FeaturePause", (True,)),
            Fact("IsGlobalPauseField", ("test::Config", "paused")),
        ]

        compute_pause_facts(ctx)

        assert has_fact(ctx.source_files["file.move"].facts, "ChecksPause", ("test::deposit",))

    def test_assert_indirect_via_variable(self):
        """Pause value in variable checked via assert! triggers ChecksPause."""
        ctx = ProjectContext(["file.move"])
        ctx.source_files["file.move"].facts = [
            Fact("Struct", ("test::Config",)),
            Fact("Fun", ("test::deposit",)),
            Fact("FieldAccess", ("test::deposit", "test::Config", "paused", "config.paused", 5)),
            Fact("FieldAssign", ("test::deposit", "stmt_1", "is_paused", "config", "paused")),
            Fact("Assigns", ("test::deposit", "stmt_1", "is_paused", ("config",))),
            # Generated from assert!(!is_paused, E_PAUSED)
            Fact("ConditionCheck", ("test::deposit", "stmt_2", ("is_paused",))),
        ]
        ctx.project_facts = [
            Fact("FeaturePause", (True,)),
            Fact("IsGlobalPauseField", ("test::Config", "paused")),
        ]

        compute_pause_facts(ctx)

        assert has_fact(ctx.source_files["file.move"].facts, "ChecksPause", ("test::deposit",))

class TestWhileLoopConditionTracking:
    """Tests for while/loop condition tracking - not yet implemented."""

    @pytest.mark.xfail(reason="While condition tracking not implemented")
    def test_while_condition_pause_check(self):
        """Pause field checked in while condition should trigger ChecksPause."""
        ctx = ProjectContext(["file.move"])
        ctx.source_files["file.move"].facts = [
            Fact("Struct", ("test::Config",)),
            Fact("Fun", ("test::process",)),
            Fact("FieldAccess", ("test::process", "test::Config", "paused", "config.paused", 5)),
            # WhileConditionFieldAccess would be needed - currently not generated
        ]
        ctx.project_facts = [
            Fact("FeaturePause", (True,)),
            Fact("IsGlobalPauseField", ("test::Config", "paused")),
        ]

        compute_pause_facts(ctx)

        assert has_fact(ctx.source_files["file.move"].facts, "ChecksPause", ("test::process",))


class TestFieldNameCollision:
    """Test that same field name in different structs doesn't cause false positives."""

    def test_same_field_name_different_struct_no_collision(self):
        """
        Two structs with same field name 'paused':
        - Config.paused = global pause (IsGlobalPauseField)
        - Offer.paused = per-object lock (NOT global pause)

        Only function checking Config.paused should get ChecksPause.
        """
        ctx = ProjectContext(["file.move"])
        ctx.source_files["file.move"].facts = [
            # Two structs with same field name
            Fact("Struct", ("test::Config",)),
            Fact("StructField", ("test::Config", 0, "paused", "bool")),
            Fact("Struct", ("test::Offer",)),
            Fact("StructField", ("test::Offer", 0, "paused", "bool")),
            # Function that checks Config.paused (global pause)
            Fact("Fun", ("test::deposit",)),
            Fact("FieldAccess", ("test::deposit", "test::Config", "paused", "config.paused", 10)),
            Fact("ConditionFieldAccess", ("test::deposit", "stmt_1", "config", "paused")),
            # Function that checks Offer.paused (per-object lock, NOT global pause)
            Fact("Fun", ("test::accept_offer",)),
            Fact("FieldAccess", ("test::accept_offer", "test::Offer", "paused", "offer.paused", 20)),
            Fact("ConditionFieldAccess", ("test::accept_offer", "stmt_2", "offer", "paused")),
        ]
        # Global pause is ONLY in Config, not Offer
        ctx.project_facts = [
            Fact("FeaturePause", (True,)),
            Fact("IsGlobalPauseField", ("test::Config", "paused")),
        ]

        compute_pause_facts(ctx)

        # deposit checks Config.paused -> should get ChecksPause
        assert has_fact(ctx.source_files["file.move"].facts, "ChecksPause", ("test::deposit",))
        # accept_offer checks Offer.paused -> should NOT get ChecksPause (different struct!)
        assert not has_fact(ctx.source_files["file.move"].facts, "ChecksPause", ("test::accept_offer",))

    def test_collision_with_variable_tracking(self):
        """
        Same collision but with variable assignment:
        - let is_paused = config.paused; if (is_paused) -> ChecksPause
        - let is_locked = offer.paused; if (is_locked) -> NO ChecksPause
        """
        ctx = ProjectContext(["file.move"])
        ctx.source_files["file.move"].facts = [
            Fact("Struct", ("test::Config",)),
            Fact("Struct", ("test::Offer",)),
            # Function checking Config.paused via variable
            Fact("Fun", ("test::deposit",)),
            Fact("FieldAccess", ("test::deposit", "test::Config", "paused", "config.paused", 10)),
            Fact("FieldAssign", ("test::deposit", "stmt_1", "is_paused", "config", "paused")),
            Fact("ConditionCheck", ("test::deposit", "stmt_2", ("is_paused",))),
            # Function checking Offer.paused via variable
            Fact("Fun", ("test::accept_offer",)),
            Fact("FieldAccess", ("test::accept_offer", "test::Offer", "paused", "offer.paused", 20)),
            Fact("FieldAssign", ("test::accept_offer", "stmt_3", "is_locked", "offer", "paused")),
            Fact("ConditionCheck", ("test::accept_offer", "stmt_4", ("is_locked",))),
        ]
        ctx.project_facts = [
            Fact("FeaturePause", (True,)),
            Fact("IsGlobalPauseField", ("test::Config", "paused")),
        ]

        compute_pause_facts(ctx)

        # deposit checks Config.paused -> ChecksPause
        assert has_fact(ctx.source_files["file.move"].facts, "ChecksPause", ("test::deposit",))
        # accept_offer checks Offer.paused -> NO ChecksPause
        assert not has_fact(ctx.source_files["file.move"].facts, "ChecksPause", ("test::accept_offer",))

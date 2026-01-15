"""
Tests for PauseDetector feature detection and ChecksPause propagation.
"""

import os
import sys
import tempfile
import textwrap


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.context import ProjectContext
from core.facts import Fact
from analysis.structural import StructuralBuilder
from features.pause import PauseDetector


class TestPauseDetectorHeuristics:
    """Test heuristic scoring for pause detection."""

    def _create_temp_move_file(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, "w") as f:
            f.write(textwrap.dedent(content))
        return path

    def test_heuristic_score_with_pause_field(self):
        """Pause-like bool field should increase score."""
        path = self._create_temp_move_file("""
            module test::example {
                public struct Config has key {
                    id: UID,
                    paused: bool,
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            detector = PauseDetector()
            score = detector.heuristic_score(ctx)
            assert score >= 0.3, f"Expected score >= 0.3 for pause field, got {score}"
        finally:
            os.unlink(path)

    def test_heuristic_score_with_pause_function(self):
        """Pause-like function name should increase score."""
        path = self._create_temp_move_file("""
            module test::example {
                public fun pause(config: &mut Config, _cap: &AdminCap) {
                    config.paused = true;
                }

                public fun unpause(config: &mut Config, _cap: &AdminCap) {
                    config.paused = false;
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            detector = PauseDetector()
            score = detector.heuristic_score(ctx)
            assert score >= 0.3, f"Expected score >= 0.3 for pause functions, got {score}"
        finally:
            os.unlink(path)

    def test_heuristic_score_no_pause(self):
        """No pause patterns should give low score."""
        path = self._create_temp_move_file("""
            module test::example {
                public struct Pool has key {
                    id: UID,
                    balance: u64,
                }

                public fun deposit(pool: &mut Pool, amount: u64) {
                    pool.balance = pool.balance + amount;
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            detector = PauseDetector()
            score = detector.heuristic_score(ctx)
            assert score < 0.3, f"Expected score < 0.3 for no pause, got {score}"
        finally:
            os.unlink(path)


class TestPauseDetectorContext:
    """Test context building for pause detection."""

    def _create_temp_move_file(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, "w") as f:
            f.write(textwrap.dedent(content))
        return path

    def test_build_context_collects_bool_fields(self):
        """Context should include structs with bool fields."""
        path = self._create_temp_move_file("""
            module test::example {
                public struct Config has key {
                    id: UID,
                    paused: bool,
                    fee: u64,
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            detector = PauseDetector()
            feature_ctx = detector.build_context(ctx)

            assert len(feature_ctx.relevant_structs) > 0, "Should find struct with bool field"
            struct = feature_ctx.relevant_structs[0]
            assert "paused" in struct["bool_fields"], "Should identify paused as bool field"
        finally:
            os.unlink(path)

    def test_build_context_collects_pause_functions(self):
        """Context should include pause-related functions."""
        path = self._create_temp_move_file("""
            module test::example {
                public fun pause(config: &mut Config, _cap: &AdminCap) {
                    config.paused = true;
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            detector = PauseDetector()
            feature_ctx = detector.build_context(ctx)

            func_names = [f["name"] for f in feature_ctx.relevant_functions]
            assert any("pause" in name.lower() for name in func_names), "Should find pause function"
        finally:
            os.unlink(path)


class TestPauseDetectorParsing:
    """Test LLM response parsing."""

    def _create_temp_move_file(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, "w") as f:
            f.write(textwrap.dedent(content))
        return path

    def test_parse_positive_response(self):
        """Positive LLM response should emit FeaturePause(True) and related facts."""
        path = self._create_temp_move_file("""
            module test::example {
                public struct Config has key {
                    id: UID,
                    paused: bool,
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            detector = PauseDetector()
            response = {
                "has_pause": True,
                "confidence": 0.9,
                "pause_struct": "test::example::Config",
                "pause_field": "paused",
                "check_functions": ["test::example::deposit", "test::example::withdraw"],
                "control_functions": ["test::example::pause", "test::example::unpause"],
            }

            facts = detector.parse_response(response, ctx)

            # Check FeaturePause
            feature_facts = [f for f in facts if f.name == "FeaturePause"]
            assert len(feature_facts) == 1
            assert feature_facts[0].args[0] is True

            # Check IsGlobalPauseField
            config_facts = [f for f in facts if f.name == "IsGlobalPauseField"]
            assert len(config_facts) == 1
            assert config_facts[0].args[0] == "test::example::Config"
            assert config_facts[0].args[1] == "paused"

            # Check ChecksPause
            check_facts = [f for f in facts if f.name == "ChecksPause"]
            assert len(check_facts) == 2

            # Check IsPauseControl
            control_facts = [f for f in facts if f.name == "IsPauseControl"]
            assert len(control_facts) == 2
        finally:
            os.unlink(path)

    def test_parse_negative_response(self):
        """Negative LLM response should emit FeaturePause(False)."""
        path = self._create_temp_move_file("""
            module test::example {
                public struct Pool has key {
                    id: UID,
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            detector = PauseDetector()
            response = {
                "has_pause": False,
                "confidence": 0.8,
                "pause_struct": "",
                "pause_field": "",
                "check_functions": [],
                "control_functions": [],
            }

            facts = detector.parse_response(response, ctx)

            assert len(facts) == 1
            assert facts[0].name == "FeaturePause"
            assert facts[0].args[0] is False
        finally:
            os.unlink(path)

    def test_parse_low_confidence_response(self):
        """Low confidence should emit FeaturePause(False)."""
        path = self._create_temp_move_file("""
            module test::example {
                public struct Config has key {
                    id: UID,
                    paused: bool,
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            detector = PauseDetector()
            response = {
                "has_pause": True,
                "confidence": 0.5,  # Below 0.7 threshold
                "pause_struct": "Config",
                "pause_field": "paused",
                "check_functions": [],
                "control_functions": [],
            }

            facts = detector.parse_response(response, ctx)

            assert len(facts) == 1
            assert facts[0].name == "FeaturePause"
            assert facts[0].args[0] is False
        finally:
            os.unlink(path)


class TestPauseNoConfig:
    """Test behavior when pause config is missing."""

    def _create_temp_move_file(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, "w") as f:
            f.write(textwrap.dedent(content))
        return path

    def test_no_checks_pause_without_pause_config(self):
        """Without IsGlobalPauseField, no propagation should happen."""
        from analysis.pause import compute_pause_facts

        path = self._create_temp_move_file("""
            module test::example {
                public struct Config has key {
                    id: UID,
                    paused: bool,
                }

                public entry fun deposit(pool: &mut Pool, amount: u64) {
                    pool.balance = pool.balance + amount;
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            # No IsGlobalPauseField in project_facts
            ctx.project_facts = [Fact("FeaturePause", (False,))]

            # Run propagation
            compute_pause_facts(ctx)

            # Should not add any ChecksPause facts
            file_ctx = ctx.source_files[path]
            checks_facts = [f for f in file_ctx.facts if f.name == "ChecksPause"]
            assert len(checks_facts) == 0, "Should not add ChecksPause without IsGlobalPauseField"
        finally:
            os.unlink(path)


class TestPauseRulesIntegration:
    """Integration tests for pause-related rules."""

    def _create_temp_move_file(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, "w") as f:
            f.write(textwrap.dedent(content))
        return path

    def test_pause_check_missing_fires(self):
        """pause-check-missing should fire for sensitive function without pause check."""
        from analysis.pause import compute_pause_facts

        path = self._create_temp_move_file("""
            module test::example {
                use sui::transfer;
                use sui::tx_context::{Self, TxContext};
                use sui::coin::{Self, Coin};

                public struct Config has key {
                    id: UID,
                    paused: bool,
                }

                public struct Pool has key {
                    id: UID,
                    balance: Balance<SUI>,
                }

                // This function checks pause - should NOT trigger
                public entry fun safe_withdraw(
                    config: &Config,
                    pool: &mut Pool,
                    amount: u64,
                    ctx: &mut TxContext
                ) {
                    assert!(!config.paused, 0);
                    let coins = coin::take(&mut pool.balance, amount, ctx);
                    transfer::public_transfer(coins, tx_context::sender(ctx));
                }

                // This function does NOT check pause - should trigger
                public entry fun unsafe_withdraw(
                    pool: &mut Pool,
                    amount: u64,
                    ctx: &mut TxContext
                ) {
                    let coins = coin::take(&mut pool.balance, amount, ctx);
                    transfer::public_transfer(coins, tx_context::sender(ctx));
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            # Simulate PauseDetector detecting pause
            ctx.project_facts = [
                Fact("FeaturePause", (True,)),
                Fact("IsGlobalPauseField", ("test::example::Config", "paused")),
                Fact("ChecksPause", ("test::example::safe_withdraw",)),
            ]

            # Run propagation
            compute_pause_facts(ctx)

            # Verify safe_withdraw has ChecksPause, unsafe_withdraw doesn't
            file_ctx = ctx.source_files[path]
            checks_facts = [f for f in file_ctx.facts if f.name == "ChecksPause"]
            checked_funcs = {f.args[0] for f in checks_facts}

            assert "test::example::safe_withdraw" in checked_funcs
            assert "test::example::unsafe_withdraw" not in checked_funcs
        finally:
            os.unlink(path)

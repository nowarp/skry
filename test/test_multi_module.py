"""
Tests documenting the 1 file == 1 module assumption bug.

The codebase currently assumes each .move file contains exactly one module.
This is typical but NOT mandatory - Move allows multiple modules per file.

These tests document the current broken behavior and will pass once fixed.
"""

import textwrap
import tempfile
import os

import pytest

from core.context import ProjectContext
from analysis import StructuralBuilder
from move.parse import parse_move_source
from move.imports import _parse_module_declaration
from test_utils import has_fact


class TestMultiModuleParsing:
    """Tests for multi-module file parsing."""

    MULTI_MODULE_SOURCE = textwrap.dedent("""
        module test::module_a {
            public struct StructA has drop {}
            public fun func_a() {}
        }

        module test::module_b {
            public struct StructB has drop {}
            public fun func_b() {}
        }
    """).strip()

    def _create_temp_move_file(self, content: str) -> str:
        """Create a temporary Move file and return its path."""
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, "w") as f:
            f.write(content)
        return path

    @pytest.mark.xfail(reason="1 file == 1 module assumption: returns single module, not all")
    def test_parse_module_declaration_returns_all_modules(self):
        """
        _parse_module_declaration() should return ALL module paths from a file.

        Current bug: Returns only the LAST module (test::module_b), not a list of all.
        This causes all functions/structs to be attributed to the wrong module.
        """
        root = parse_move_source(self.MULTI_MODULE_SOURCE)
        result = _parse_module_declaration(self.MULTI_MODULE_SOURCE, root)

        # Current broken behavior: returns "test::module_b" (last module)
        # Expected: should return list ["test::module_a", "test::module_b"]
        assert isinstance(result, list), (
            f"Expected list of module paths, got single value: {result}"
        )
        assert len(result) == 2, f"Expected 2 modules, got: {result}"

    @pytest.mark.xfail(reason="1 file == 1 module assumption: second module's facts are missing")
    def test_structural_builder_generates_facts_for_all_modules(self):
        """
        StructuralBuilder should generate facts for ALL modules in a file.

        Currently only the first module's facts are generated.
        """
        path = self._create_temp_move_file(self.MULTI_MODULE_SOURCE)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)
            facts = ctx.source_files[path].facts

            # First module should have facts (this works)
            assert has_fact(facts, "Fun", ("test::module_a::func_a",)), (
                "Expected Fun fact for module_a::func_a"
            )

            # Second module should ALSO have facts (this fails)
            assert has_fact(facts, "Fun", ("test::module_b::func_b",)), (
                "Expected Fun fact for module_b::func_b - second module is not parsed"
            )
        finally:
            os.unlink(path)

    @pytest.mark.xfail(reason="1 file == 1 module assumption: structs misattributed to wrong module")
    def test_struct_facts_correct_module_qualification(self):
        """
        Struct facts should use correct module qualification.

        Current bug: ALL structs are qualified with the LAST module's path.
        So StructA from module_a becomes test::module_b::StructA (WRONG!)
        """
        path = self._create_temp_move_file(self.MULTI_MODULE_SOURCE)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)
            facts = ctx.source_files[path].facts

            # StructA should be qualified with module_a, not module_b
            assert has_fact(facts, "Struct", ("test::module_a::StructA",)), (
                "Expected Struct fact for test::module_a::StructA"
            )

            # This is the bug: StructA is wrongly qualified with module_b
            wrong_qualified = has_fact(facts, "Struct", ("test::module_b::StructA",))
            assert not wrong_qualified, (
                "BUG: StructA is wrongly qualified as test::module_b::StructA"
            )
        finally:
            os.unlink(path)


class TestMultiModuleRealWorld:
    """Tests based on real-world multi-module files found in projects/sui/."""

    @pytest.mark.xfail(reason="1 file == 1 module assumption")
    def test_coins_test_pattern(self):
        """
        Pattern from suitears/coins.test.move: multiple test coin modules in one file.
        """
        source = textwrap.dedent("""
            #[test_only]
            module suitears::s_eth {
                public struct S_ETH has drop {}
                public fun init_for_testing() {}
            }

            #[test_only]
            module suitears::s_btc {
                public struct S_BTC has drop {}
                public fun init_for_testing() {}
            }
        """).strip()

        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, "w") as f:
            f.write(source)

        try:
            ctx = ProjectContext([path])
            # Note: skip_tests=False to analyze test_only modules
            StructuralBuilder(skip_tests=False).build(ctx)
            facts = ctx.source_files[path].facts

            # Both modules should have their init_for_testing function
            assert has_fact(facts, "Fun", ("suitears::s_eth::init_for_testing",))
            assert has_fact(facts, "Fun", ("suitears::s_btc::init_for_testing",)), (
                "Second module (s_btc) is not parsed"
            )
        finally:
            os.unlink(path)

"""Tests for find_struct_instantiations() FQN matching.

The bug: Simple name matching causes wrong struct attribution when
different modules have structs with the same simple name.

Example: module_a::Factory and module_b::Factory - if module_a creates
Factory, it should NOT be attributed as a creation site for module_b::Factory.
"""

import textwrap
import tempfile
import os

from core.context import ProjectContext
from analysis import StructuralBuilder
from analysis.patterns import find_struct_instantiations, collect_creation_sites
from move.parse import parse_move_source


class TestFindStructInstantiationsFQNMatching:
    """Test that find_struct_instantiations uses FQN matching, not simple name."""

    def test_same_named_structs_different_modules_no_cross_match(self):
        """
        When two modules have structs with same simple name (Factory),
        creation site in module_a should NOT match module_b::Factory.

        This is the core bug: simple name matching causes cross-module misattribution.
        """
        source_a = textwrap.dedent("""
            module test::module_a {
                public struct Factory has key { id: UID }

                fun init(ctx: &mut TxContext) {
                    let factory = Factory { id: object::new(ctx) };
                    transfer::share_object(factory);
                }
            }
        """)

        source_b = textwrap.dedent("""
            module test::module_b {
                public struct Factory has key { id: UID }

                fun init(ctx: &mut TxContext) {
                    let factory = Factory { id: object::new(ctx) };
                    transfer::transfer(factory, tx_context::sender(ctx));
                }
            }
        """)

        # Create temp files
        fd_a, path_a = tempfile.mkstemp(suffix=".move")
        fd_b, path_b = tempfile.mkstemp(suffix=".move")

        with os.fdopen(fd_a, "w") as f:
            f.write(source_a)
        with os.fdopen(fd_b, "w") as f:
            f.write(source_b)

        try:
            ctx = ProjectContext([path_a, path_b])
            StructuralBuilder().build(ctx)

            # Collect creation sites
            creation_sites = collect_creation_sites(ctx)

            # module_a::Factory should have creation site in module_a::init
            assert "test::module_a::Factory" in creation_sites, (
                "module_a::Factory should have creation sites"
            )
            a_sites = creation_sites["test::module_a::Factory"]
            a_funcs = [s.func_name for s in a_sites]
            assert "test::module_a::init" in a_funcs, (
                "module_a::Factory should be created in module_a::init"
            )

            # module_b::Factory should have creation site in module_b::init
            assert "test::module_b::Factory" in creation_sites, (
                "module_b::Factory should have creation sites"
            )
            b_sites = creation_sites["test::module_b::Factory"]
            b_funcs = [s.func_name for s in b_sites]
            assert "test::module_b::init" in b_funcs, (
                "module_b::Factory should be created in module_b::init"
            )

            # CRITICAL: module_a::Factory should NOT have module_b::init as creation site
            assert "test::module_b::init" not in a_funcs, (
                "BUG: module_a::Factory wrongly attributed to module_b::init due to simple name matching"
            )

            # CRITICAL: module_b::Factory should NOT have module_a::init as creation site
            assert "test::module_a::init" not in b_funcs, (
                "BUG: module_b::Factory wrongly attributed to module_a::init due to simple name matching"
            )

        finally:
            os.unlink(path_a)
            os.unlink(path_b)

    def test_find_struct_instantiations_fqn_priority(self):
        """
        Direct test of find_struct_instantiations: FQN match should take priority.

        When pack expression uses qualified name (module_a::Factory),
        it should only match target struct with same FQN.
        """
        source = textwrap.dedent("""
            module test::creator {
                use test::module_a::Factory as FactoryA;

                fun create_a(ctx: &mut TxContext) {
                    let f = test::module_a::Factory { id: object::new(ctx) };
                    transfer::share_object(f);
                }
            }
        """)

        root = parse_move_source(source)

        # Search for both Factory types
        target_structs = {"test::module_a::Factory", "test::module_b::Factory"}
        results = find_struct_instantiations(source, root, target_structs)

        # Should find module_a::Factory (explicit FQN in pack)
        func_to_structs = {}
        for func, struct in results:
            func_to_structs.setdefault(func, set()).add(struct)

        creator_structs = func_to_structs.get("test::creator::create_a", set())

        assert "test::module_a::Factory" in creator_structs, (
            "Should find test::module_a::Factory from explicit FQN pack"
        )
        assert "test::module_b::Factory" not in creator_structs, (
            "BUG: Should NOT match test::module_b::Factory - different FQN"
        )

    def test_simple_name_same_module_still_works(self):
        """
        Simple name matching should still work within same module.

        When pack expression uses simple name (Factory) in module_a,
        it should match target test::module_a::Factory.
        """
        source = textwrap.dedent("""
            module test::module_a {
                public struct Factory has key { id: UID }

                fun init(ctx: &mut TxContext) {
                    let f = Factory { id: object::new(ctx) };
                    transfer::share_object(f);
                }
            }
        """)

        root = parse_move_source(source)

        # Search for module_a::Factory
        target_structs = {"test::module_a::Factory"}
        results = find_struct_instantiations(source, root, target_structs)

        func_to_structs = {}
        for func, struct in results:
            func_to_structs.setdefault(func, set()).add(struct)

        init_structs = func_to_structs.get("test::module_a::init", set())

        assert "test::module_a::Factory" in init_structs, (
            "Simple name should match struct in same module"
        )


class TestCrossModuleCreationSites:
    """Test that structs created in different modules are correctly discovered."""

    def test_struct_created_in_different_module(self):
        """
        When module_b creates module_a::Config using FQN pack,
        the creation site should be found in module_b.

        This tests cross-module creation site discovery.
        """
        # Module A defines Config struct but doesn't create it
        source_a = textwrap.dedent("""
            module test::module_a {
                public struct Config has key { id: UID, value: u64 }
            }
        """)

        # Module B creates module_a::Config
        source_b = textwrap.dedent("""
            module test::module_b {
                use test::module_a::Config;

                fun setup(ctx: &mut TxContext) {
                    let config = test::module_a::Config { id: object::new(ctx), value: 0 };
                    transfer::share_object(config);
                }
            }
        """)

        fd_a, path_a = tempfile.mkstemp(suffix=".move")
        fd_b, path_b = tempfile.mkstemp(suffix=".move")

        with os.fdopen(fd_a, "w") as f:
            f.write(source_a)
        with os.fdopen(fd_b, "w") as f:
            f.write(source_b)

        try:
            ctx = ProjectContext([path_a, path_b])
            StructuralBuilder().build(ctx)

            creation_sites = collect_creation_sites(ctx)

            # module_a::Config should have creation site in module_b::setup
            assert "test::module_a::Config" in creation_sites, (
                "module_a::Config should have creation sites (created in module_b)"
            )
            sites = creation_sites["test::module_a::Config"]
            func_names = [s.func_name for s in sites]
            assert "test::module_b::setup" in func_names, (
                "module_a::Config should be created in module_b::setup"
            )

            # Verify transfer pattern is correct
            setup_site = next(s for s in sites if s.func_name == "test::module_b::setup")
            assert setup_site.shared is True, (
                "Config should be shared"
            )

        finally:
            os.unlink(path_a)
            os.unlink(path_b)

    def test_struct_created_in_multiple_modules(self):
        """
        When a struct is created in multiple modules,
        all creation sites should be discovered.
        """
        # Module A defines Config
        source_a = textwrap.dedent("""
            module test::types {
                public struct SharedState has key { id: UID }
            }
        """)

        # Module B creates SharedState in init
        source_b = textwrap.dedent("""
            module test::module_b {
                fun init(ctx: &mut TxContext) {
                    let state = test::types::SharedState { id: object::new(ctx) };
                    transfer::share_object(state);
                }
            }
        """)

        # Module C also creates SharedState
        source_c = textwrap.dedent("""
            module test::module_c {
                fun create_state(ctx: &mut TxContext) {
                    let state = test::types::SharedState { id: object::new(ctx) };
                    transfer::transfer(state, tx_context::sender(ctx));
                }
            }
        """)

        fd_a, path_a = tempfile.mkstemp(suffix=".move")
        fd_b, path_b = tempfile.mkstemp(suffix=".move")
        fd_c, path_c = tempfile.mkstemp(suffix=".move")

        with os.fdopen(fd_a, "w") as f:
            f.write(source_a)
        with os.fdopen(fd_b, "w") as f:
            f.write(source_b)
        with os.fdopen(fd_c, "w") as f:
            f.write(source_c)

        try:
            ctx = ProjectContext([path_a, path_b, path_c])
            StructuralBuilder().build(ctx)

            creation_sites = collect_creation_sites(ctx)

            # SharedState should have creation sites from both module_b and module_c
            assert "test::types::SharedState" in creation_sites, (
                "SharedState should have creation sites"
            )
            sites = creation_sites["test::types::SharedState"]
            func_names = [s.func_name for s in sites]

            assert "test::module_b::init" in func_names, (
                "SharedState should be created in module_b::init"
            )
            assert "test::module_c::create_state" in func_names, (
                "SharedState should be created in module_c::create_state"
            )

            # Verify different transfer patterns
            b_site = next(s for s in sites if s.func_name == "test::module_b::init")
            c_site = next(s for s in sites if s.func_name == "test::module_c::create_state")

            assert b_site.shared is True, "module_b shares the state"
            assert c_site.transferred_to == "sender", "module_c transfers to sender"

        finally:
            os.unlink(path_a)
            os.unlink(path_b)
            os.unlink(path_c)

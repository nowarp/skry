"""Tests for _find_per_struct_transfer_patterns FQN matching.

The bug: Simple name matching causes wrong struct's transfer pattern attribution
when different modules have structs with the same simple name.

Example: module_a::Config is shared, module_b::Config is transferred.
If module_a::init creates and shares Config, module_b::Config should NOT
be attributed as shared due to simple name matching.
"""

import textwrap
import tempfile
import os

from core.context import ProjectContext
from analysis import StructuralBuilder
from analysis.patterns import collect_creation_sites, _find_per_struct_transfer_patterns
from move.parse import parse_move_source


class TestPerStructTransferPatternsFQNMatching:
    """Test that _find_per_struct_transfer_patterns uses FQN matching."""

    def test_same_named_structs_different_transfer_patterns(self):
        """
        When two modules have structs with same simple name (Config),
        and module_a shares it while module_b transfers it,
        each struct should get its correct pattern.

        This is the core bug: simple name matching causes cross-module misattribution.
        """
        source_a = textwrap.dedent("""
            module test::module_a {
                public struct Config has key { id: UID, value: u64 }

                fun init(ctx: &mut TxContext) {
                    let config = Config { id: object::new(ctx), value: 0 };
                    transfer::share_object(config);
                }
            }
        """)

        source_b = textwrap.dedent("""
            module test::module_b {
                public struct Config has key { id: UID, admin: address }

                fun init(ctx: &mut TxContext) {
                    let config = Config { id: object::new(ctx), admin: tx_context::sender(ctx) };
                    transfer::transfer(config, tx_context::sender(ctx));
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

            # module_a::Config should be SHARED
            assert "test::module_a::Config" in creation_sites, (
                "module_a::Config should have creation sites"
            )
            a_sites = creation_sites["test::module_a::Config"]
            assert len(a_sites) == 1, "Should have exactly one creation site"
            a_site = a_sites[0]
            assert a_site.shared is True, (
                "module_a::Config should be shared"
            )
            assert a_site.transferred_to == "none", (
                "module_a::Config should NOT be transferred"
            )

            # module_b::Config should be TRANSFERRED TO SENDER
            assert "test::module_b::Config" in creation_sites, (
                "module_b::Config should have creation sites"
            )
            b_sites = creation_sites["test::module_b::Config"]
            assert len(b_sites) == 1, "Should have exactly one creation site"
            b_site = b_sites[0]
            assert b_site.transferred_to == "sender", (
                "module_b::Config should be transferred to sender"
            )
            assert b_site.shared is False, (
                "BUG: module_b::Config wrongly marked as shared due to simple name matching"
            )

        finally:
            os.unlink(path_a)
            os.unlink(path_b)

    def test_same_named_structs_one_shared_one_frozen(self):
        """
        Different transfer patterns: module_a shares, module_b freezes.
        Each should get correct pattern without cross-contamination.
        """
        source_a = textwrap.dedent("""
            module test::registry_a {
                public struct Registry has key { id: UID }

                fun init(ctx: &mut TxContext) {
                    let reg = Registry { id: object::new(ctx) };
                    transfer::share_object(reg);
                }
            }
        """)

        source_b = textwrap.dedent("""
            module test::registry_b {
                public struct Registry has key { id: UID }

                fun init(ctx: &mut TxContext) {
                    let reg = Registry { id: object::new(ctx) };
                    transfer::freeze_object(reg);
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

            # registry_a::Registry should be SHARED
            assert "test::registry_a::Registry" in creation_sites
            a_sites = creation_sites["test::registry_a::Registry"]
            a_site = a_sites[0]
            assert a_site.shared is True, "registry_a::Registry should be shared"
            assert a_site.frozen is False, "registry_a::Registry should NOT be frozen"

            # registry_b::Registry should be FROZEN
            assert "test::registry_b::Registry" in creation_sites
            b_sites = creation_sites["test::registry_b::Registry"]
            b_site = b_sites[0]
            assert b_site.frozen is True, "registry_b::Registry should be frozen"
            assert b_site.shared is False, (
                "BUG: registry_b::Registry wrongly marked as shared due to simple name matching"
            )

        finally:
            os.unlink(path_a)
            os.unlink(path_b)

    def test_same_module_simple_name_still_works(self):
        """
        Simple name matching should still work within same module.
        When init uses simple name 'Config', it should correctly match
        the module's own Config struct.
        """
        source = textwrap.dedent("""
            module test::single {
                public struct Config has key { id: UID }

                fun init(ctx: &mut TxContext) {
                    let c = Config { id: object::new(ctx) };
                    transfer::share_object(c);
                }
            }
        """)

        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, "w") as f:
            f.write(source)

        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            creation_sites = collect_creation_sites(ctx)

            assert "test::single::Config" in creation_sites
            sites = creation_sites["test::single::Config"]
            site = sites[0]
            assert site.shared is True, "Config should be shared"

        finally:
            os.unlink(path)

    def test_fqn_pack_expression_correct_attribution(self):
        """
        When pack expression uses FQN like `test::module_a::Factory { ... }`,
        the transfer pattern should be attributed to the correct struct.

        This tests that extract_struct_name_from_pack handles module_identity.
        """
        source = textwrap.dedent("""
            module test::creator {
                public struct Factory has key { id: UID }

                fun init(ctx: &mut TxContext) {
                    let f = test::creator::Factory { id: object::new(ctx) };
                    transfer::share_object(f);
                }
            }
        """)

        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, "w") as f:
            f.write(source)

        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            creation_sites = collect_creation_sites(ctx)

            # The FQN pack should be correctly attributed
            assert "test::creator::Factory" in creation_sites, (
                "Factory should have creation sites when using FQN pack"
            )
            sites = creation_sites["test::creator::Factory"]
            site = sites[0]
            assert site.shared is True, "Factory should be shared"

        finally:
            os.unlink(path)

    def test_cross_module_fqn_pack_transfer_pattern(self):
        """
        When module_a::helper creates and shares module_b::Config using FQN pack,
        the transfer pattern should be attributed to module_b::Config, not module_a::Config.

        This is the core bug: extract_struct_name_from_pack doesn't handle module_identity,
        so FQN packs like `test::module_b::Config { ... }` are misattributed.
        """
        source_a = textwrap.dedent("""
            module test::module_a {
                public struct Config has key { id: UID }

                fun init(ctx: &mut TxContext) {
                    let a = Config { id: object::new(ctx) };
                    transfer::transfer(a, tx_context::sender(ctx));
                }
            }
        """)

        source_b = textwrap.dedent("""
            module test::module_b {
                public struct Config has key { id: UID }
            }
        """)

        # Module C creates module_b::Config using FQN and shares it
        source_c = textwrap.dedent("""
            module test::module_c {
                use test::module_b::Config;

                fun create_and_share(ctx: &mut TxContext) {
                    let b = test::module_b::Config { id: object::new(ctx) };
                    transfer::share_object(b);
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

            # module_a::Config is transferred to sender in module_a::init
            assert "test::module_a::Config" in creation_sites
            a_sites = creation_sites["test::module_a::Config"]
            a_site = a_sites[0]
            assert a_site.transferred_to == "sender", "module_a::Config should be transferred to sender"
            assert a_site.shared is False, "module_a::Config should NOT be shared"

            # module_b::Config is created in module_c::create_and_share and shared
            assert "test::module_b::Config" in creation_sites, (
                "module_b::Config should have creation sites from module_c"
            )
            b_sites = creation_sites["test::module_b::Config"]
            b_site = b_sites[0]
            assert b_site.func_name == "test::module_c::create_and_share", (
                f"Expected creation in module_c::create_and_share, got {b_site.func_name}"
            )
            assert b_site.shared is True, (
                "BUG: module_b::Config should be shared but extract_struct_name_from_pack "
                "doesn't handle module_identity in FQN pack expressions"
            )

        finally:
            os.unlink(path_a)
            os.unlink(path_b)
            os.unlink(path_c)


class TestFindPerStructTransferPatternsDirect:
    """Direct tests of _find_per_struct_transfer_patterns function."""

    def test_fqn_pack_with_multiple_same_named_targets(self):
        """
        When target_structs contains multiple same-named structs from different modules,
        and the function creates one using FQN, it should be correctly attributed.

        This is the core bug: simple name matching can match the wrong target when
        there are multiple targets with the same simple name.
        """
        source = textwrap.dedent("""
            module test::creator {
                fun create_b(ctx: &mut TxContext) {
                    let b = test::module_b::Config { id: object::new(ctx) };
                    transfer::share_object(b);
                }
            }
        """)

        root = parse_move_source(source)

        # Both module_a::Config and module_b::Config are in target_structs
        # The function creates module_b::Config, so only module_b::Config should be shared
        target_structs = {"test::module_a::Config", "test::module_b::Config"}

        patterns = _find_per_struct_transfer_patterns(
            source_code=source,
            root=root,
            func_name="test::creator::create_b",
            target_structs=target_structs,
            import_map={},
            module_path="test::creator",
        )

        # module_b::Config should be shared
        assert patterns["test::module_b::Config"].shared is True, (
            "module_b::Config should be shared (created with FQN pack)"
        )
        assert patterns["test::module_b::Config"].transferred_to == "none", (
            "module_b::Config should not be transferred"
        )

        # module_a::Config should NOT be shared - it wasn't created in this function
        assert patterns["test::module_a::Config"].shared is False, (
            "BUG: module_a::Config wrongly marked as shared due to simple name matching"
        )
        assert patterns["test::module_a::Config"].transferred_to == "none", (
            "module_a::Config should not be transferred"
        )

    def test_simple_name_pack_correct_module_matching(self):
        """
        When pack uses simple name (no FQN), it should match the struct from
        the current module only, not from other modules.
        """
        source = textwrap.dedent("""
            module test::module_a {
                fun init(ctx: &mut TxContext) {
                    let c = Config { id: object::new(ctx) };
                    transfer::share_object(c);
                }
            }
        """)

        root = parse_move_source(source)

        # Both module_a::Config and module_b::Config are in target_structs
        target_structs = {"test::module_a::Config", "test::module_b::Config"}

        patterns = _find_per_struct_transfer_patterns(
            source_code=source,
            root=root,
            func_name="test::module_a::init",
            target_structs=target_structs,
            import_map={},
            module_path="test::module_a",
        )

        # module_a::Config should be shared (simple name in same module)
        assert patterns["test::module_a::Config"].shared is True, (
            "module_a::Config should be shared"
        )

        # module_b::Config should NOT be shared - different module
        assert patterns["test::module_b::Config"].shared is False, (
            "BUG: module_b::Config wrongly marked as shared due to simple name matching"
        )

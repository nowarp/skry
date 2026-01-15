"""Tests for StructuralBuilder - fact collection and single-parse guarantee."""
import textwrap
import tempfile
import os

from core.context import ProjectContext
from analysis import StructuralBuilder
from test_utils import has_fact, get_facts


class TestStructuralBuilderParsing:
    """Test that StructuralBuilder parses files correctly."""

    def _create_temp_move_file(self, content: str) -> str:
        """Create a temporary Move file and return its path."""
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, 'w') as f:
            f.write(textwrap.dedent(content))
        return path

    def test_parses_and_stores_in_file_ctx(self):
        """After build(), SourceFileContext should have root and source_code."""
        path = self._create_temp_move_file("""
            module test::example {
                public fun hello() {}
            }
        """)
        try:
            ctx = ProjectContext([path])
            builder = StructuralBuilder()
            builder.build(ctx)

            file_ctx = ctx.source_files[path]
            assert file_ctx.source_code is not None
            assert file_ctx.root is not None
            assert file_ctx.source_code_hash is not None
            assert len(file_ctx.facts) > 0
        finally:
            os.unlink(path)

    def test_generates_function_facts(self):
        """Should generate Fun, IsPublic, IsEntry facts."""
        path = self._create_temp_move_file("""
            module test::example {
                fun private_func() {}
                public fun public_func() {}
                entry fun entry_func() {}
                public entry fun public_entry_func() {}
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)
            facts = ctx.source_files[path].facts

            # All functions should have Fun fact
            assert has_fact(facts, "Fun", ("test::example::private_func",))
            assert has_fact(facts, "Fun", ("test::example::public_func",))
            assert has_fact(facts, "Fun", ("test::example::entry_func",))
            assert has_fact(facts, "Fun", ("test::example::public_entry_func",))

            # Check modifiers
            assert not has_fact(facts, "IsPublic", ("test::example::private_func",))
            assert has_fact(facts, "IsPublic", ("test::example::public_func",))
            assert not has_fact(facts, "IsPublic", ("test::example::entry_func",))
            assert has_fact(facts, "IsPublic", ("test::example::public_entry_func",))

            assert not has_fact(facts, "IsEntry", ("test::example::private_func",))
            assert not has_fact(facts, "IsEntry", ("test::example::public_func",))
            assert has_fact(facts, "IsEntry", ("test::example::entry_func",))
            assert has_fact(facts, "IsEntry", ("test::example::public_entry_func",))
        finally:
            os.unlink(path)

    def test_public_package_generates_is_friend(self):
        """public(package) functions should generate IsFriend fact."""
        path = self._create_temp_move_file("""
            module test::example {
                public fun regular_public() {}
                public(package) fun package_internal() {}
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)
            facts = ctx.source_files[path].facts

            # Regular public should NOT have IsFriend
            assert not has_fact(facts, "IsFriend", ("test::example::regular_public",))

            # public(package) SHOULD have IsFriend
            assert has_fact(facts, "IsFriend", ("test::example::package_internal",))

            # Both should have IsPublic (it's still public, just scoped)
            assert has_fact(facts, "IsPublic", ("test::example::regular_public",))
            assert has_fact(facts, "IsPublic", ("test::example::package_internal",))
        finally:
            os.unlink(path)

    def test_public_package_with_space_generates_is_friend(self):
        """public (package) with space should also generate IsFriend fact."""
        path = self._create_temp_move_file("""
            module test::example {
                public (package) fun package_internal_with_space() {}
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)
            facts = ctx.source_files[path].facts
            assert has_fact(facts, "IsFriend", ("test::example::package_internal_with_space",))
        finally:
            os.unlink(path)

    def test_skips_test_functions(self):
        """Functions with #[test] or #[test_only] annotation should be skipped."""
        path = self._create_temp_move_file("""
            module test::example {
                public fun normal_func() {}

                #[test]
                public fun simple_test() {}

                #[test(account = @0x1)]
                public entry fun test_with_args(): address {
                    @0x1
                }

                #[test_only]
                public fun test_only_func() {}
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)
            facts = ctx.source_files[path].facts

            # Normal function should be present
            assert has_fact(facts, "Fun", ("test::example::normal_func",))

            # All test functions should be skipped (including #[test_only])
            assert not has_fact(facts, "Fun", ("test::example::simple_test",))
            assert not has_fact(facts, "Fun", ("test::example::test_with_args",))
            assert not has_fact(facts, "Fun", ("test::example::test_only_func",))
        finally:
            os.unlink(path)

    def test_generates_struct_facts(self):
        """Should generate Struct, StructField, IsCapability facts."""
        path = self._create_temp_move_file("""
            module test::example {
                public struct AdminCap has key {
                    id: UID,
                }
                public struct Treasury has key {
                    balance: u64,
                    owner: address,
                }

                fun init(ctx: &mut TxContext) {
                    let cap = AdminCap { id: object::new(ctx) };
                    transfer::transfer(cap, tx_context::sender(ctx));
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)
            facts = ctx.source_files[path].facts

            assert has_fact(facts, "Struct", ("test::example::AdminCap",))
            assert has_fact(facts, "Struct", ("test::example::Treasury",))

            # IsCapability for AdminCap (single-UID + name pattern + init transfer)
            assert has_fact(facts, "IsCapability", ("test::example::AdminCap",))
            assert not has_fact(facts, "IsCapability", ("test::example::Treasury",))

            # StructField facts
            field_facts = get_facts(facts, "StructField")
            treasury_fields = [f for f in field_facts if "Treasury" in f.args[0]]
            assert len(treasury_fields) == 2
        finally:
            os.unlink(path)

    def test_generates_formal_arg_facts(self):
        """Should generate FormalArg facts for function parameters."""
        path = self._create_temp_move_file("""
            module test::example {
                public fun transfer(cap: &AdminCap, amount: u64, ctx: &mut TxContext) {}
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)
            facts = ctx.source_files[path].facts

            formal_args = get_facts(facts, "FormalArg")
            func_args = [f for f in formal_args if f.args[0] == "test::example::transfer"]

            assert len(func_args) == 3

            # Check arg order and types
            arg0 = next(f for f in func_args if f.args[1] == 0)
            arg1 = next(f for f in func_args if f.args[1] == 1)
            arg2 = next(f for f in func_args if f.args[1] == 2)

            assert arg0.args[2] == "cap"
            assert arg1.args[2] == "amount"
            assert arg2.args[2] == "ctx"
        finally:
            os.unlink(path)

    def test_generates_call_facts(self):
        """Should generate Call, InFun, ActualArg facts."""
        path = self._create_temp_move_file("""
            module test::example {
                use sui::transfer;

                public fun do_transfer(obj: Object, recipient: address) {
                    transfer::transfer(obj, recipient);
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)
            facts = ctx.source_files[path].facts

            call_facts = get_facts(facts, "Call")
            assert len(call_facts) >= 1

            in_fun_facts = get_facts(facts, "InFun")
            assert len(in_fun_facts) >= 1
        finally:
            os.unlink(path)


class TestStructuralBuilderGlobalIndex:
    """Test global facts index building."""

    def _create_temp_move_file(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, 'w') as f:
            f.write(textwrap.dedent(content))
        return path

    def test_builds_global_index(self):
        """Global index should map function names to facts."""
        path = self._create_temp_move_file("""
            module test::example {
                public fun foo() {}
                public fun bar() {}
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            assert "test::example::foo" in ctx.global_facts_index
            assert "test::example::bar" in ctx.global_facts_index

            # Each function should have facts indexed
            foo_facts = ctx.global_facts_index["test::example::foo"][path]
            assert any(f.name == "Fun" for f in foo_facts)
            assert any(f.name == "IsPublic" for f in foo_facts)
        finally:
            os.unlink(path)

    def test_location_map_populated(self):
        """Location map should be populated for entities."""
        path = self._create_temp_move_file("""
            module test::example {
                public fun foo() {}
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            assert path in ctx.all_location_maps
            location_map = ctx.all_location_maps[path]
            assert "test::example::foo" in location_map
        finally:
            os.unlink(path)


class TestChecksCapabilityGeneration:
    """Test ChecksCapability fact generation after Pass 1."""

    def _create_temp_move_file(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, 'w') as f:
            f.write(textwrap.dedent(content))
        return path

    def test_generates_checks_role_for_role_param(self):
        """Function with role-typed param should get ChecksCapability fact."""
        path = self._create_temp_move_file("""
            module test::example {
                public struct AdminCap has key {
                    id: UID,
                }

                fun init(ctx: &mut TxContext) {
                    let cap = AdminCap { id: object::new(ctx) };
                    transfer::transfer(cap, tx_context::sender(ctx));
                }

                public fun admin_only(cap: &AdminCap) {}
                public fun public_func(x: u64) {}
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            # ChecksCapability should be in the function's indexed facts
            admin_facts = ctx.global_facts_index.get("test::example::admin_only", {}).get(path, [])
            checks_role = [f for f in admin_facts if f.name == "ChecksCapability"]
            assert len(checks_role) == 1
            assert checks_role[0].args == ("test::example::AdminCap", "test::example::admin_only")

            # public_func should NOT have ChecksCapability
            public_facts = ctx.global_facts_index.get("test::example::public_func", {}).get(path, [])
            checks_role_public = [f for f in public_facts if f.name == "ChecksCapability"]
            assert len(checks_role_public) == 0
        finally:
            os.unlink(path)


class TestTransfersFactGeneration:
    """Test Transfers fact generation - structural, not LLM."""

    def _create_temp_move_file(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, 'w') as f:
            f.write(textwrap.dedent(content))
        return path

    def test_direct_transfer_call_generates_fact(self):
        """Function calling transfer::transfer should get Transfers fact."""
        path = self._create_temp_move_file("""
            module test::example {
                public fun do_transfer(obj: SomeObject, recipient: address) {
                    transfer::transfer(obj, recipient);
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            file_ctx = ctx.source_files[path]
            transfers_facts = [f for f in file_ctx.facts if f.name == "Transfers"]
            assert len(transfers_facts) == 1
            assert transfers_facts[0].args[0] == "test::example::do_transfer"
            assert transfers_facts[0].args[1] is True
        finally:
            os.unlink(path)

    def test_public_transfer_generates_fact(self):
        """Function calling transfer::public_transfer should get Transfers fact."""
        path = self._create_temp_move_file("""
            module test::example {
                public fun send_coins(coin: Coin<SUI>, recipient: address) {
                    transfer::public_transfer(coin, recipient);
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            file_ctx = ctx.source_files[path]
            transfers_facts = [f for f in file_ctx.facts if f.name == "Transfers"]
            assert len(transfers_facts) == 1
            assert "send_coins" in transfers_facts[0].args[0]
        finally:
            os.unlink(path)

    def test_coin_transfer_generates_fact(self):
        """Function calling coin::transfer should get Transfers fact."""
        path = self._create_temp_move_file("""
            module test::example {
                public fun pay(coin: Coin<SUI>, recipient: address) {
                    coin::transfer(coin, recipient);
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            file_ctx = ctx.source_files[path]
            transfers_facts = [f for f in file_ctx.facts if f.name == "Transfers"]
            assert len(transfers_facts) == 1
        finally:
            os.unlink(path)

    def test_no_transfer_call_no_fact(self):
        """Function without transfer calls should NOT get Transfers fact."""
        path = self._create_temp_move_file("""
            module test::example {
                public fun compute(x: u64): u64 {
                    x * 2
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            file_ctx = ctx.source_files[path]
            transfers_facts = [f for f in file_ctx.facts if f.name == "Transfers"]
            assert len(transfers_facts) == 0
        finally:
            os.unlink(path)

    def test_direct_transfer_only(self):
        """Only functions with direct transfer calls should get Transfers fact (no propagation)."""
        path = self._create_temp_move_file("""
            module test::example {
                fun inner_transfer(obj: SomeObject, recipient: address) {
                    transfer::transfer(obj, recipient);
                }

                public fun outer_caller(obj: SomeObject, recipient: address) {
                    inner_transfer(obj, recipient);
                }

                public fun no_transfer(x: u64): u64 {
                    x + 1
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            file_ctx = ctx.source_files[path]
            transfers_facts = [f for f in file_ctx.facts if f.name == "Transfers"]

            # Only inner_transfer has direct transfer call
            func_names_with_transfer = {f.args[0] for f in transfers_facts}
            assert "test::example::inner_transfer" in func_names_with_transfer

            # outer_caller only calls inner_transfer, no direct transfer - use taint analysis instead
            assert "test::example::outer_caller" not in func_names_with_transfer

            # no_transfer should NOT have Transfers fact
            assert "test::example::no_transfer" not in func_names_with_transfer
        finally:
            os.unlink(path)

    def test_multiple_transfer_functions(self):
        """Multiple functions with transfer calls should all get Transfers facts."""
        path = self._create_temp_move_file("""
            module test::example {
                public fun transfer_a(obj: Object, to: address) {
                    transfer::transfer(obj, to);
                }

                public fun transfer_b(coin: Coin, to: address) {
                    transfer::public_transfer(coin, to);
                }

                public fun no_transfer() {
                    let x = 1;
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            file_ctx = ctx.source_files[path]
            transfers_facts = [f for f in file_ctx.facts if f.name == "Transfers"]

            func_names_with_transfer = {f.args[0] for f in transfers_facts}
            assert "test::example::transfer_a" in func_names_with_transfer
            assert "test::example::transfer_b" in func_names_with_transfer
            assert "test::example::no_transfer" not in func_names_with_transfer
        finally:
            os.unlink(path)


class TestIsInitFact:
    """Test IsInit fact generation for init functions."""

    def _create_temp_move_file(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, 'w') as f:
            f.write(textwrap.dedent(content))
        return path

    def test_init_function_generates_isinit(self):
        """Function named 'init' should get IsInit fact."""
        path = self._create_temp_move_file("""
            module test::example {
                public struct AdminCap has key {
                    id: UID,
                }

                fun init(ctx: &mut TxContext) {
                    let admin = AdminCap { id: object::new(ctx) };
                    transfer::transfer(admin, tx_context::sender(ctx));
                }

                public fun other_func() {}
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            file_ctx = ctx.source_files[path]
            init_facts = [f for f in file_ctx.facts if f.name == "IsInit"]

            assert len(init_facts) == 1
            assert "init" in init_facts[0].args[0]
        finally:
            os.unlink(path)

    def test_non_init_function_no_isinit(self):
        """Functions not named 'init' should NOT get IsInit fact."""
        path = self._create_temp_move_file("""
            module test::example {
                public fun initialize() {}
                public fun setup() {}
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            file_ctx = ctx.source_files[path]
            init_facts = [f for f in file_ctx.facts if f.name == "IsInit"]

            assert len(init_facts) == 0
        finally:
            os.unlink(path)


class TestIsPrivilegedDetection:
    """Test IsPrivileged detection via unified struct classification."""

    def _create_temp_move_file(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, 'w') as f:
            f.write(textwrap.dedent(content))
        return path

    def test_role_created_once_in_init_is_privileged(self):
        """Role created in init and transferred to sender should be classified as privileged."""
        from unittest.mock import patch
        from semantic_facts_builder import SemanticFactsBuilder

        path = self._create_temp_move_file("""
            module test::example {
                public struct AdminCap has key {
                    id: UID,
                }

                fun init(ctx: &mut TxContext) {
                    let admin = AdminCap { id: object::new(ctx) };
                    transfer::transfer(admin, tx_context::sender(ctx));
                }
            }
        """)
        try:
            # Mock LLM to confirm privileged role (patch where it's imported)
            with patch("semantic_facts_builder.call_llm_json") as mock_llm:
                mock_llm.return_value = {
                    "is_role": True,
                    "is_privileged": True,
                    "is_user_asset": False,
                    "is_config": False,
                    "config_fields": [],
                    "privileged_fields": [],
                    "pause_fields": [],
                }

                ctx = ProjectContext([path])
                StructuralBuilder().build(ctx)
                # Unified classification in SemanticFactsBuilder (Pass 2)
                SemanticFactsBuilder()._classify_struct_and_fields(ctx)

                file_ctx = ctx.source_files[path]
                priv_facts = [f for f in file_ctx.facts if f.name == "IsPrivileged"]

                assert len(priv_facts) == 1
                assert "AdminCap" in priv_facts[0].args[0]
        finally:
            os.unlink(path)

    def test_role_without_privileged_flag_not_privileged(self):
        """Role where LLM returns is_privileged=False should NOT get IsPrivileged fact."""
        from unittest.mock import patch
        from semantic_facts_builder import SemanticFactsBuilder

        path = self._create_temp_move_file("""
            module test::example {
                public struct ModeratorCap has key {
                    id: UID,
                }

                public fun create_moderator(ctx: &mut TxContext): ModeratorCap {
                    ModeratorCap { id: object::new(ctx) }
                }
            }
        """)
        try:
            # Mock LLM to reject privileged status (patch where it's imported)
            with patch("semantic_facts_builder.call_llm_json") as mock_llm:
                mock_llm.return_value = {
                    "is_role": True,
                    "is_privileged": False,  # Not privileged
                    "is_user_asset": False,
                    "is_config": False,
                    "config_fields": [],
                    "privileged_fields": [],
                    "pause_fields": [],
                }

                ctx = ProjectContext([path])
                StructuralBuilder().build(ctx)
                SemanticFactsBuilder()._classify_struct_and_fields(ctx)

                file_ctx = ctx.source_files[path]
                priv_facts = [f for f in file_ctx.facts if f.name == "IsPrivileged"]

                # Should have NotPrivileged, not IsPrivileged
                assert len(priv_facts) == 0
                not_priv_facts = [f for f in file_ctx.facts if f.name == "NotPrivileged"]
                assert len(not_priv_facts) == 1
        finally:
            os.unlink(path)


class TestCallsSenderGeneration:
    """Test CallsSender fact generation."""

    def _create_temp_move_file(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, 'w') as f:
            f.write(textwrap.dedent(content))
        return path

    def test_function_calling_sender_has_calls_sender(self):
        """Function calling tx_context::sender should get CallsSender fact."""
        path = self._create_temp_move_file("""
            module test::example {
                fun init(ctx: &mut TxContext) {
                    let sender = tx_context::sender(ctx);
                    transfer::transfer(obj, sender);
                }

                public fun no_sender_check() {}
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            file_ctx = ctx.source_files[path]
            calls_sender_facts = [f for f in file_ctx.facts if f.name == "CallsSender"]

            assert len(calls_sender_facts) == 1
            assert "init" in calls_sender_facts[0].args[0]
        finally:
            os.unlink(path)

    def test_function_not_calling_sender_no_fact(self):
        """Function not calling tx_context::sender should NOT get CallsSender fact."""
        path = self._create_temp_move_file("""
            module test::example {
                public fun no_sender(x: u64) {
                    let y = x + 1;
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            file_ctx = ctx.source_files[path]
            calls_sender_facts = [f for f in file_ctx.facts if f.name == "CallsSender"]

            assert len(calls_sender_facts) == 0
        finally:
            os.unlink(path)

    # Note: Call graph propagation of CallsSender has been removed.
    # Transitive protection is now tracked per-sink via GuardedSink facts.
    # See test_guarded_sinks.py for the new approach.


class TestChecksCapabilityWithoutArg:
    """Test checks_role property without argument (any role check)."""

    def _create_temp_move_file(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, 'w') as f:
            f.write(textwrap.dedent(content))
        return path

    def test_function_with_role_param_has_checks_role(self):
        """Function with role parameter should match 'f is checks_role'."""
        path = self._create_temp_move_file("""
            module test::example {
                public struct AdminCap has key {
                    id: UID,
                }

                fun init(ctx: &mut TxContext) {
                    let cap = AdminCap { id: object::new(ctx) };
                    transfer::transfer(cap, tx_context::sender(ctx));
                }

                public fun admin_only(_: &AdminCap) {}
                public fun no_role(x: u64) {}
            }
        """)
        try:
            ctx = ProjectContext([path])
            StructuralBuilder().build(ctx)

            # ChecksCapability facts are stored in global_facts_index, not in file_ctx.facts
            checks_role_facts = []
            for func_name, file_facts in ctx.global_facts_index.items():
                for fp, facts in file_facts.items():
                    for f in facts:
                        if f.name == "ChecksCapability":
                            checks_role_facts.append(f)

            # Should have ChecksCapability for admin_only
            func_names = [f.args[1] for f in checks_role_facts]
            assert any("admin_only" in fn for fn in func_names)
            # no_role shouldn't have ChecksCapability
            assert not any("no_role" in fn for fn in func_names)
        finally:
            os.unlink(path)

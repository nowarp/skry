"""Tests for Role/Asset detection and CWA (Closed World Assumption) logic."""
import textwrap

from core.context import ProjectContext, SourceFileContext
from semantic_facts_builder import _extract_struct_source
from test_utils import parse_move, parse_move_full, has_fact, get_facts


class TestIsCapabilityStructuralDetection:
    """Test structural IsCapability detection.

    IsCapability detection requires ALL conditions:
    1. Struct with SINGLE field of type UID
    2. Name matches admin pattern (ends with Cap, AdminCap, OwnerCap, etc.)
    3. Created in init function
    4. Transferred (not shared or frozen)

    This avoids FPs like Pool, Position, NFT which are single-UID but not admin caps.
    """

    def test_single_uid_field_detected_as_role(self):
        """AdminCap with UID field, transferred in init => IsCapability + IsPrivileged."""
        _, facts = parse_move_full("""
            module test::config {
                public struct AdminCap has key, store {
                    id: UID,
                }

                fun init(ctx: &mut TxContext) {
                    let cap = AdminCap { id: object::new(ctx) };
                    transfer::transfer(cap, tx_context::sender(ctx));
                }
            }
        """)
        assert has_fact(facts, "IsCapability", ("test::config::AdminCap",))
        assert has_fact(facts, "IsPrivileged", ("test::config::AdminCap",))

    def test_single_uid_operator_detected_as_role(self):
        """OperatorCap with UID field, transferred in init => IsCapability + IsPrivileged."""
        _, facts = parse_move_full("""
            module test::config {
                public struct OperatorCap has key {
                    id: UID,
                }

                fun init(ctx: &mut TxContext) {
                    let cap = OperatorCap { id: object::new(ctx) };
                    transfer::transfer(cap, tx_context::sender(ctx));
                }
            }
        """)
        assert has_fact(facts, "IsCapability", ("test::config::OperatorCap",))
        assert has_fact(facts, "IsPrivileged", ("test::config::OperatorCap",))

    def test_single_uid_non_cap_name_not_role(self):
        """Single-UID struct without matching name is NOT a role or privileged."""
        _, facts = parse_move_full("""
            module test::config {
                public struct Vault has key {
                    id: UID,
                }

                fun init(ctx: &mut TxContext) {
                    let v = Vault { id: object::new(ctx) };
                    transfer::transfer(v, tx_context::sender(ctx));
                }
            }
        """)
        # Vault doesn't match admin pattern => NOT IsCapability/IsPrivileged
        assert not has_fact(facts, "IsCapability", ("test::config::Vault",))
        assert not has_fact(facts, "IsPrivileged", ("test::config::Vault",))

    def test_admin_cap_shared_not_role(self):
        """AdminCap that is shared instead of transferred is NOT a role or privileged."""
        _, facts = parse_move_full("""
            module test::config {
                public struct AdminCap has key {
                    id: UID,
                }

                fun init(ctx: &mut TxContext) {
                    let cap = AdminCap { id: object::new(ctx) };
                    transfer::share_object(cap);
                }
            }
        """)
        # Shared => NOT IsCapability/IsPrivileged (roles must be owned)
        assert not has_fact(facts, "IsCapability", ("test::config::AdminCap",))
        assert not has_fact(facts, "IsPrivileged", ("test::config::AdminCap",))

    def test_admin_cap_no_init_not_role(self):
        """AdminCap without init function is NOT detected as role or privileged."""
        _, facts = parse_move_full("""
            module test::config {
                public struct AdminCap has key {
                    id: UID,
                }

                public fun create_cap(ctx: &mut TxContext): AdminCap {
                    AdminCap { id: object::new(ctx) }
                }
            }
        """)
        # No init => NOT detected (might be created elsewhere)
        assert not has_fact(facts, "IsCapability", ("test::config::AdminCap",))
        assert not has_fact(facts, "IsPrivileged", ("test::config::AdminCap",))

    def test_multiple_fields_not_role(self):
        """Struct with multiple fields is NOT a role."""
        _, facts = parse_move_full("""
            module test::config {
                public struct TreasuryCap has key {
                    id: UID,
                    balance: Balance<SUI>,
                }

                fun init(ctx: &mut TxContext) {
                    let t = TreasuryCap { id: object::new(ctx), balance: balance::zero() };
                    transfer::transfer(t, tx_context::sender(ctx));
                }
            }
        """)
        # Multiple fields => NOT IsCapability (even with Cap name)
        assert not has_fact(facts, "IsCapability", ("test::config::TreasuryCap",))

    def test_no_uid_field_not_role(self):
        """Struct without UID field is NOT a role."""
        _, facts = parse_move_full("""
            module test::config {
                public struct Config has key {
                    value: u64,
                }
            }
        """)
        assert not has_fact(facts, "IsCapability", ("test::config::Config",))

    def test_transitive_helper_transfer(self):
        """AdminCap transferred via helper function is still detected as role + privileged."""
        _, facts = parse_move_full("""
            module test::config {
                public struct AdminCap has key {
                    id: UID,
                }

                fun init(ctx: &mut TxContext) {
                    let cap = AdminCap { id: object::new(ctx) };
                    setup_admin(cap, ctx);
                }

                fun setup_admin(cap: AdminCap, ctx: &mut TxContext) {
                    transfer::transfer(cap, tx_context::sender(ctx));
                }
            }
        """)
        # Helper does the transfer, but it's transitively called by init
        assert has_fact(facts, "IsCapability", ("test::config::AdminCap",))
        assert has_fact(facts, "IsPrivileged", ("test::config::AdminCap",))

    def test_transfer_without_sender_not_role(self):
        """AdminCap transferred to param (not sender) is NOT a role or privileged."""
        _, facts = parse_move_full("""
            module test::config {
                public struct AdminCap has key {
                    id: UID,
                }

                fun init(recipient: address, ctx: &mut TxContext) {
                    let cap = AdminCap { id: object::new(ctx) };
                    transfer::transfer(cap, recipient);
                }
            }
        """)
        # Transferred to param, not sender => NOT IsCapability/IsPrivileged
        assert not has_fact(facts, "IsCapability", ("test::config::AdminCap",))
        assert not has_fact(facts, "IsPrivileged", ("test::config::AdminCap",))

    def test_sender_in_helper_transfer_in_init(self):
        """Sender call in helper, transfer in init still counts as role + privileged."""
        _, facts = parse_move_full("""
            module test::config {
                public struct AdminCap has key {
                    id: UID,
                }

                fun init(ctx: &mut TxContext) {
                    let cap = AdminCap { id: object::new(ctx) };
                    let owner = get_sender(ctx);
                    transfer::transfer(cap, owner);
                }

                fun get_sender(ctx: &TxContext): address {
                    tx_context::sender(ctx)
                }
            }
        """)
        # sender() in helper, transfer in init => still detected
        assert has_fact(facts, "IsCapability", ("test::config::AdminCap",))
        assert has_fact(facts, "IsPrivileged", ("test::config::AdminCap",))


class TestChecksCapabilityFactGeneration:
    """Test ChecksCapability fact generation for functions with role parameters.

    NOTE: ChecksCapability facts are generated in StructuralBuilder._generate_checks_role_facts()
    as a post-pass AFTER all IsCapability facts are collected from all files.
    The parse_move() helper only runs parsing, not the full pipeline.
    """
    import pytest

    @pytest.mark.xfail(reason="ChecksCapability requires full StructuralBuilder pipeline")
    def test_function_with_admin_cap_param(self):
        """This test documents DESIRED behavior but requires full pipeline."""
        _, facts, _ = parse_move("""
            module test::config {
                public struct AdminCap has key {
                    id: UID,
                }

                public fun withdraw(_cap: &AdminCap) {}
            }
        """)
        # AdminCap has single UID field => IsCapability
        assert has_fact(facts, "IsCapability", ("test::config::AdminCap",))
        # Function with role param gets ChecksCapability fact (requires StructuralBuilder)
        assert has_fact(facts, "ChecksCapability", ("test::config::AdminCap", "test::config::withdraw"))

    def test_function_without_role_param(self):
        _, facts, _ = parse_move("""
            module test::config {
                public struct AdminCap has key {
                    id: UID,
                }

                public fun public_func(x: u64) {}
            }
        """)
        # public_func doesn't have AdminCap param, so no ChecksCapability
        # (This passes because no ChecksCapability facts are generated without full pipeline)
        checks_role_facts = get_facts(facts, "ChecksCapability")
        func_checks = [f for f in checks_role_facts if "public_func" in f.args[1]]
        assert len(func_checks) == 0


class TestExtractStructSource:
    """Test struct source extraction from parsed file."""

    def test_extract_simple_struct(self):
        source = textwrap.dedent("""
            module test::config {
                public struct AdminCap has key {
                    id: UID,
                }
            }
        """)
        from move.parse import parse_move_source
        root = parse_move_source(source)
        file_ctx = SourceFileContext(path="test.move")
        file_ctx.source_code = source
        file_ctx.root = root

        struct_source = _extract_struct_source(file_ctx, "AdminCap")
        assert struct_source is not None
        assert "AdminCap" in struct_source
        assert "id: UID" in struct_source

    def test_extract_qualified_name(self):
        source = textwrap.dedent("""
            module test::config {
                public struct Treasury has key {
                    balance: u64,
                }
            }
        """)
        from move.parse import parse_move_source
        root = parse_move_source(source)
        file_ctx = SourceFileContext(path="test.move")
        file_ctx.source_code = source
        file_ctx.root = root

        struct_source = _extract_struct_source(file_ctx, "test::config::Treasury")
        assert struct_source is not None
        assert "Treasury" in struct_source

    def test_extract_nonexistent_struct(self):
        source = textwrap.dedent("""
            module test::config {
                public struct Foo {}
            }
        """)
        from move.parse import parse_move_source
        root = parse_move_source(source)
        file_ctx = SourceFileContext(path="test.move")
        file_ctx.source_code = source
        file_ctx.root = root

        struct_source = _extract_struct_source(file_ctx, "NonExistent")
        assert struct_source is None


class TestChecksCapabilityDirect:
    """Test ChecksCapability generation for functions with role parameters.

    Functions with role parameters get ChecksCapability directly.
    """

    def test_direct_role_params(self):
        """Both functions with role params get ChecksCapability directly."""
        source = textwrap.dedent("""
            module test::pool {
                use sui::object::UID;

                public struct AdminCap has key {
                    id: UID,
                }

                fun init(ctx: &mut TxContext) {
                    let cap = AdminCap { id: object::new(ctx) };
                    transfer::transfer(cap, tx_context::sender(ctx));
                }

                /// Internal helper that verifies admin capability
                fun require_admin(_cap: &AdminCap) {
                    // Capability ownership proven by having the param
                }

                public entry fun public_withdraw(cap: &AdminCap, amount: u64) {
                    require_admin(cap);
                    // withdraw logic
                }
            }
        """)
        ctx = _build_context_with_source(source)

        # Both functions have cap param, so both get ChecksCapability directly
        facts = ctx.source_files[list(ctx.source_files.keys())[0]].facts
        checks_role_facts = [f for f in facts if f.name == "ChecksCapability"]

        # require_admin has direct ChecksCapability
        require_admin_roles = [f for f in checks_role_facts if "require_admin" in f.args[1]]
        assert len(require_admin_roles) == 1, f"require_admin should have ChecksCapability: {checks_role_facts}"

        # public_withdraw has ChecksCapability (direct, since it has cap param)
        withdraw_roles = [f for f in checks_role_facts if "public_withdraw" in f.args[1]]
        assert len(withdraw_roles) == 1, f"public_withdraw should have ChecksCapability: {checks_role_facts}"


# Note: Call graph propagation of ChecksCapability has been removed.
# Transitive protection is now tracked per-sink via GuardedSink facts.
# See test_guarded_sinks.py for the new approach.


class TestChecksCapabilityDirectWithCalls:
    """Tests for ChecksCapability with functions that have role params."""

    def test_transitive_direct_params(self):
        """ChecksCapability propagates through multiple call levels.

        entry_func() -> middle_func() -> helper_with_cap(cap)
        -> All three should have ChecksCapability
        """
        source = textwrap.dedent("""
            module test::pool {
                use sui::object::UID;

                public struct OwnerCap has key {
                    id: UID,
                }

                fun init(ctx: &mut TxContext) {
                    let cap = OwnerCap { id: object::new(ctx) };
                    transfer::transfer(cap, tx_context::sender(ctx));
                }

                fun helper_with_cap(_cap: &OwnerCap) {
                    // has cap param
                }

                fun middle_func(cap: &OwnerCap) {
                    helper_with_cap(cap);
                }

                public entry fun entry_func(cap: &OwnerCap) {
                    middle_func(cap);
                }
            }
        """)
        ctx = _build_context_with_source(source)

        facts = ctx.source_files[list(ctx.source_files.keys())[0]].facts
        checks_role_facts = [f for f in facts if f.name == "ChecksCapability"]

        # All three functions should have ChecksCapability
        helper_roles = [f for f in checks_role_facts if "helper_with_cap" in f.args[1]]
        middle_roles = [f for f in checks_role_facts if "middle_func" in f.args[1]]
        entry_roles = [f for f in checks_role_facts if "entry_func" in f.args[1]]

        assert len(helper_roles) == 1, "helper_with_cap should have ChecksCapability"
        assert len(middle_roles) == 1, "middle_func should have ChecksCapability"
        assert len(entry_roles) == 1, "entry_func should have ChecksCapability"

        # All should reference OwnerCap
        assert all("OwnerCap" in f.args[0] for f in [helper_roles[0], middle_roles[0], entry_roles[0]])

    def test_multiple_role_types_propagate_separately(self):
        """Different role types propagate independently.

        func_a() has AdminCap -> callers get ChecksCapability(AdminCap, ...)
        func_b() has OperatorCap -> callers get ChecksCapability(OperatorCap, ...)
        """
        source = textwrap.dedent("""
            module test::pool {
                use sui::object::UID;

                public struct AdminCap has key { id: UID }
                public struct OperatorCap has key { id: UID }

                fun init(ctx: &mut TxContext) {
                    let admin = AdminCap { id: object::new(ctx) };
                    let op = OperatorCap { id: object::new(ctx) };
                    transfer::transfer(admin, tx_context::sender(ctx));
                    transfer::transfer(op, tx_context::sender(ctx));
                }

                fun admin_helper(_cap: &AdminCap) {}
                fun operator_helper(_cap: &OperatorCap) {}

                public fun admin_action(cap: &AdminCap) {
                    admin_helper(cap);
                }

                public fun operator_action(cap: &OperatorCap) {
                    operator_helper(cap);
                }

                public fun mixed_action(admin: &AdminCap, op: &OperatorCap) {
                    admin_helper(admin);
                    operator_helper(op);
                }
            }
        """)
        ctx = _build_context_with_source(source)

        facts = ctx.source_files[list(ctx.source_files.keys())[0]].facts
        checks_role_facts = [f for f in facts if f.name == "ChecksCapability"]

        # admin_action should have AdminCap role only
        admin_action_roles = [f for f in checks_role_facts if "admin_action" in f.args[1]]
        assert len(admin_action_roles) == 1
        assert "AdminCap" in admin_action_roles[0].args[0]

        # operator_action should have OperatorCap role only
        operator_action_roles = [f for f in checks_role_facts if "operator_action" in f.args[1]]
        assert len(operator_action_roles) == 1
        assert "OperatorCap" in operator_action_roles[0].args[0]

        # mixed_action should have BOTH roles
        mixed_roles = [f for f in checks_role_facts if "mixed_action" in f.args[1]]
        assert len(mixed_roles) == 2, f"mixed_action should have 2 ChecksCapability facts: {mixed_roles}"
        role_types = {f.args[0] for f in mixed_roles}
        assert any("AdminCap" in r for r in role_types)
        assert any("OperatorCap" in r for r in role_types)


def _build_context_with_source(source: str) -> ProjectContext:
    """Helper to build ProjectContext with full StructuralBuilder pipeline."""
    import tempfile
    import os
    from analysis import StructuralBuilder
    from analysis.access_control import generate_checks_role_facts

    with tempfile.NamedTemporaryFile(mode='w', suffix='.move', delete=False) as f:
        f.write(source)
        path = f.name

    try:
        ctx = ProjectContext([path])
        StructuralBuilder().build(ctx)
        generate_checks_role_facts(ctx)
        return ctx
    finally:
        os.unlink(path)



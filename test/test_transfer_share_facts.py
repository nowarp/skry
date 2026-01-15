"""Tests for TransfersToSender and SharesObject fact generation with value flow tracking.

These tests verify that when an init() function packs multiple structs,
each struct correctly gets its own fact based on which operation it's passed to.
"""

from test_utils import parse_move_full, has_fact


class TestTransferShareFacts:
    """Test correct TransfersToSender and SharesObject generation with value flow."""

    def test_separate_transfer_and_share_in_init(self):
        """
        When init packs two structs and transfers one, shares another,
        each struct should get the correct fact - NOT both facts.

        This is the core test case for the FP fix.
        """
        _, facts = parse_move_full("""
            module test::pool {
                public struct PoolCap has key { id: UID }
                public struct PoolRegistry has key { id: UID }

                fun init(ctx: &mut TxContext) {
                    let pool_cap = PoolCap { id: object::new(ctx) };
                    let pool_registry = PoolRegistry { id: object::new(ctx) };

                    transfer::share_object(pool_registry);
                    transfer::transfer(pool_cap, tx_context::sender(ctx));
                }
            }
        """)

        # PoolCap: transferred to sender, NOT shared
        assert has_fact(facts, "TransfersToSender", ("test::pool::init", "test::pool::PoolCap"))
        assert not has_fact(facts, "SharesObject", ("test::pool::init", "test::pool::PoolCap"))

        # PoolRegistry: shared, NOT transferred
        assert has_fact(facts, "SharesObject", ("test::pool::init", "test::pool::PoolRegistry"))
        assert not has_fact(facts, "TransfersToSender", ("test::pool::init", "test::pool::PoolRegistry"))

        # Role detection: only PoolCap should be a role (if it has privileged name)
        # PoolRegistry is shared, so it should NOT be a role even if named *Cap
        assert not has_fact(facts, "IsCapability", ("test::pool::PoolRegistry",))

    def test_single_struct_transfer_to_sender(self):
        """Single struct transferred to sender gets correct facts."""
        _, facts = parse_move_full("""
            module test::admin {
                public struct AdminCap has key { id: UID }

                fun init(ctx: &mut TxContext) {
                    let cap = AdminCap { id: object::new(ctx) };
                    transfer::transfer(cap, tx_context::sender(ctx));
                }
            }
        """)

        assert has_fact(facts, "TransfersToSender", ("test::admin::init", "test::admin::AdminCap"))
        assert not has_fact(facts, "SharesObject", ("test::admin::init", "test::admin::AdminCap"))
        assert has_fact(facts, "IsCapability", ("test::admin::AdminCap",))
        assert has_fact(facts, "IsPrivileged", ("test::admin::AdminCap",))

    def test_single_struct_shared(self):
        """Single struct shared gets SharesObject, not IsCapability."""
        _, facts = parse_move_full("""
            module test::config {
                public struct Config has key { id: UID }

                fun init(ctx: &mut TxContext) {
                    let config = Config { id: object::new(ctx), value: 0 };
                    transfer::share_object(config);
                }
            }
        """)

        assert has_fact(facts, "SharesObject", ("test::config::init", "test::config::Config"))
        assert not has_fact(facts, "TransfersToSender", ("test::config::init", "test::config::Config"))
        # Config is not a privileged role name, so no IsCapability
        assert not has_fact(facts, "IsCapability", ("test::config::Config",))

    def test_shared_admin_cap_not_role(self):
        """AdminCap that is shared should NOT be IsCapability - sharing defeats access control."""
        _, facts = parse_move_full("""
            module test::bad {
                public struct AdminCap has key { id: UID }

                fun init(ctx: &mut TxContext) {
                    let cap = AdminCap { id: object::new(ctx) };
                    transfer::share_object(cap);
                }
            }
        """)

        assert has_fact(facts, "SharesObject", ("test::bad::init", "test::bad::AdminCap"))
        assert not has_fact(facts, "TransfersToSender", ("test::bad::init", "test::bad::AdminCap"))
        # Shared caps are NOT roles even with privileged name
        assert not has_fact(facts, "IsCapability", ("test::bad::AdminCap",))

    def test_multiple_caps_different_operations(self):
        """Multiple caps in init - one transferred, one shared."""
        _, facts = parse_move_full("""
            module test::dual {
                public struct AdminCap has key { id: UID }
                public struct OperatorCap has key { id: UID }

                fun init(ctx: &mut TxContext) {
                    let admin = AdminCap { id: object::new(ctx) };
                    let operator = OperatorCap { id: object::new(ctx) };

                    transfer::transfer(admin, tx_context::sender(ctx));
                    transfer::share_object(operator);
                }
            }
        """)

        # AdminCap: transferred only
        assert has_fact(facts, "TransfersToSender", ("test::dual::init", "test::dual::AdminCap"))
        assert not has_fact(facts, "SharesObject", ("test::dual::init", "test::dual::AdminCap"))

        # OperatorCap: shared only
        assert has_fact(facts, "SharesObject", ("test::dual::init", "test::dual::OperatorCap"))
        assert not has_fact(facts, "TransfersToSender", ("test::dual::init", "test::dual::OperatorCap"))

        # Only AdminCap is a role (transferred to sender)
        assert has_fact(facts, "IsCapability", ("test::dual::AdminCap",))
        assert not has_fact(facts, "IsCapability", ("test::dual::OperatorCap",))

    def test_packs_to_var_fact_generation(self):
        """Verify PacksToVar facts are generated correctly."""
        _, facts = parse_move_full("""
            module test::pack {
                public struct MyStruct has key { id: UID }

                fun init(ctx: &mut TxContext) {
                    let my_var = MyStruct { id: object::new(ctx) };
                    transfer::transfer(my_var, tx_context::sender(ctx));
                }
            }
        """)

        # Should have PacksToVar fact linking variable to struct type
        assert has_fact(facts, "PacksToVar", ("test::pack::init", "my_var", "test::pack::MyStruct"))


class TestValueFlowEdgeCases:
    """Edge cases for value flow tracking."""

    def test_parameter_transfer_generates_fact(self):
        """TransfersToSender generated when parameter is transferred to sender."""
        _, facts = parse_move_full("""
            module test::external {
                public struct External has key { id: UID }

                fun transfer_external(obj: External, ctx: &TxContext) {
                    transfer::transfer(obj, tx_context::sender(ctx));
                }
            }
        """)

        # obj is a parameter - we track its type via FormalArg, so TransfersToSender is generated
        assert has_fact(facts, "TransfersToSender", ("test::external::transfer_external", "test::external::External"))

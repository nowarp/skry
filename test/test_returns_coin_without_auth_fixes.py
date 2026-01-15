"""Tests for returns-coin-without-auth false positive fixes."""
from core.facts import Fact
from analysis.derived_facts import compute_derived_facts, _compute_value_exchange_facts
from test_utils import has_fact, parse_move_full


class TestImmutableReferenceSkip:
    """Test Fix 1: Immutable references to Coin/Balance types should not trigger ReturnsCoinType."""

    def test_immutable_balance_ref_not_flagged(self):
        """Returning &Balance<T> (immutable ref) should NOT generate ReturnsCoinType fact."""
        code = """
            module test::pool {
                use sui::balance::Balance;

                public struct Pool<phantom T> has key {
                    id: UID,
                    reserves: Balance<T>,
                }

                public fun get_reserves<T>(self: &Pool<T>): &Balance<T> {
                    &self.reserves
                }
            }
        """

        ctx, facts = parse_move_full(code)

        # Should NOT have ReturnsCoinType for immutable ref
        assert not has_fact(facts, "ReturnsCoinType", ("test::pool::get_reserves", "Balance<T>"))

    def test_owned_balance_still_flagged(self):
        """Returning owned Balance<T> should still generate ReturnsCoinType fact."""
        code = """
            module test::pool {
                use sui::balance::Balance;

                public fun extract<T>(b: &mut Balance<T>, amount: u64): Balance<T> {
                    balance::split(b, amount)
                }
            }
        """

        ctx, facts = parse_move_full(code)

        # SHOULD have ReturnsCoinType for owned value
        assert has_fact(facts, "ReturnsCoinType", ("test::pool::extract", "sui::balance::Balance<T>"))

    def test_mut_ref_balance_still_flagged(self):
        """Returning &mut Balance<T> should still generate ReturnsCoinType fact."""
        code = """
            module test::pool {
                use sui::balance::Balance;

                public struct Pool<phantom T> has key {
                    id: UID,
                    reserves: Balance<T>,
                }

                public fun get_reserves_mut<T>(self: &mut Pool<T>): &mut Balance<T> {
                    &mut self.reserves
                }
            }
        """

        ctx, facts = parse_move_full(code)

        # SHOULD have ReturnsCoinType for mutable ref
        assert has_fact(facts, "ReturnsCoinType", ("test::pool::get_reserves_mut", "sui::balance::Balance<T>"))

    def test_owned_coin_still_flagged(self):
        """Returning owned Coin<T> should still generate ReturnsCoinType fact."""
        code = """
            module test::pool {
                use sui::coin::Coin;

                public fun withdraw<T>(amount: u64, ctx: &mut TxContext): Coin<T> {
                    // dangerous!
                    coin::mint(amount, ctx)
                }
            }
        """

        ctx, facts = parse_move_full(code)

        # SHOULD have ReturnsCoinType for owned Coin
        assert has_fact(facts, "ReturnsCoinType", ("test::pool::withdraw", "sui::coin::Coin<T>"))


class TestValueExchangeFunction:
    """Test Fix 2: Value exchange pattern (coin input + coin output) should be recognized."""

    def test_value_exchange_detected(self):
        """Function with Coin input and Coin output should generate ValueExchangeFunction fact."""
        facts = [
            Fact("FormalArg", ("test::swap", 0, "input_coin", "Coin<SUI>")),
            Fact("ReturnsCoinType", ("test::swap", "Coin<SUI>")),
        ]

        result = _compute_value_exchange_facts(facts)

        assert len(result) == 1
        assert result[0].name == "ValueExchangeFunction"
        assert result[0].args == ("test::swap",)

    def test_balance_exchange_detected(self):
        """Function with Balance input and Balance output should generate ValueExchangeFunction fact."""
        facts = [
            Fact("FormalArg", ("test::refund", 0, "input", "Balance<T>")),
            Fact("ReturnsCoinType", ("test::refund", "Balance<T>")),
        ]

        result = _compute_value_exchange_facts(facts)

        assert len(result) == 1
        assert result[0].name == "ValueExchangeFunction"

    def test_borrowed_coin_not_exchange(self):
        """Function with &Coin or &mut Coin input should NOT be value exchange."""
        facts = [
            Fact("FormalArg", ("test::peek", 0, "coin_ref", "&Coin<SUI>")),
            Fact("ReturnsCoinType", ("test::peek", "Coin<SUI>")),
        ]

        result = _compute_value_exchange_facts(facts)

        # Not value exchange - input is borrowed, not owned
        assert len(result) == 0

    def test_no_coin_input_not_exchange(self):
        """Function with no Coin input should NOT be value exchange."""
        facts = [
            Fact("FormalArg", ("test::mint", 0, "amount", "u64")),
            Fact("ReturnsCoinType", ("test::mint", "Coin<SUI>")),
        ]

        result = _compute_value_exchange_facts(facts)

        # Not value exchange - no coin input
        assert len(result) == 0

    def test_full_integration(self):
        """Test value exchange detection in full pipeline."""
        code = """
            module test::swap {
                use sui::coin::Coin;
                use sui::tx_context::TxContext;

                public fun purchase_ticket<T>(
                    purchase_coin: Coin<T>,
                    ctx: &mut TxContext
                ): Coin<T> {
                    // Process payment, return refund
                    purchase_coin
                }
            }
        """

        ctx, facts = parse_move_full(code)

        # Compute derived facts
        compute_derived_facts(ctx)

        # Should have ValueExchangeFunction fact (check in updated facts after derived computation)
        file_ctx = list(ctx.source_files.values())[0]
        assert has_fact(file_ctx.facts, "ValueExchangeFunction", ("test::swap::purchase_ticket",))

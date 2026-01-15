"""Tests for generic type validation analysis."""

from core.facts import Fact
from taint.generics import (
    _parse_generic_type,
    detect_phantom_type_bindings,
    detect_extracted_value_returned,
)


class TestParseGenericType:
    """Test _parse_generic_type helper function."""

    def test_simple_generic(self):
        """Pool<T> -> ("Pool", ["T"])"""
        struct_name, type_args = _parse_generic_type("Pool<T>")
        assert struct_name == "Pool"
        assert type_args == ["T"]

    def test_with_mut_ref(self):
        """&mut LiquidStakingInfo<P> -> ("LiquidStakingInfo", ["P"])"""
        struct_name, type_args = _parse_generic_type("&mut LiquidStakingInfo<P>")
        assert struct_name == "LiquidStakingInfo"
        assert type_args == ["P"]

    def test_with_ref(self):
        """&Pool<T> -> ("Pool", ["T"])"""
        struct_name, type_args = _parse_generic_type("&Pool<T>")
        assert struct_name == "Pool"
        assert type_args == ["T"]

    def test_multiple_type_args(self):
        """Pair<A, B> -> ("Pair", ["A", "B"])"""
        struct_name, type_args = _parse_generic_type("Pair<A, B>")
        assert struct_name == "Pair"
        assert type_args == ["A", "B"]

    def test_non_generic_type(self):
        """u64 -> (None, [])"""
        struct_name, type_args = _parse_generic_type("u64")
        assert struct_name is None
        assert type_args == []

    def test_fqn_generic(self):
        """module::Pool<T> -> ("module::Pool", ["T"])"""
        struct_name, type_args = _parse_generic_type("module::Pool<T>")
        assert struct_name == "module::Pool"
        assert type_args == ["T"]


class TestDetectPhantomTypeBindings:
    """Test phantom type binding detection."""

    def test_simple_phantom_binding(self):
        """
        struct Pool<phantom T> { ... }
        fun withdraw<P>(pool: &mut Pool<P>) { ... }
        -> TypeBoundByPhantom(withdraw, P, Pool, pool)
        """
        facts = [
            # Function has generic param P
            Fact("HasGenericParam", ("test::withdraw", 0, "P")),
            # Function has param pool of type Pool<P>
            Fact("FormalArg", ("test::withdraw", 0, "pool", "&mut Pool<P>")),
            # Pool has phantom type param at position 0
            Fact("StructPhantomTypeParam", ("Pool", 0, "T")),
        ]

        result = detect_phantom_type_bindings("test::withdraw", facts)

        assert len(result) == 1
        assert result[0].name == "TypeBoundByPhantom"
        assert result[0].args == ("test::withdraw", "P", "Pool", "pool")

    def test_multiple_phantom_params(self):
        """
        struct Pair<phantom A, phantom B> { ... }
        fun swap<X, Y>(pair: &mut Pair<X, Y>) { ... }
        -> TypeBoundByPhantom for both X and Y
        """
        facts = [
            Fact("HasGenericParam", ("test::swap", 0, "X")),
            Fact("HasGenericParam", ("test::swap", 1, "Y")),
            Fact("FormalArg", ("test::swap", 0, "pair", "&mut Pair<X, Y>")),
            Fact("StructPhantomTypeParam", ("Pair", 0, "A")),
            Fact("StructPhantomTypeParam", ("Pair", 1, "B")),
        ]

        result = detect_phantom_type_bindings("test::swap", facts)

        assert len(result) == 2
        assert any(f.args == ("test::swap", "X", "Pair", "pair") for f in result)
        assert any(f.args == ("test::swap", "Y", "Pair", "pair") for f in result)

    def test_mixed_phantom_non_phantom(self):
        """
        struct Mixed<phantom T, U> { ... }
        fun extract<A, B>(mixed: &mut Mixed<A, B>) { ... }
        -> TypeBoundByPhantom only for A (not B)
        """
        facts = [
            Fact("HasGenericParam", ("test::extract", 0, "A")),
            Fact("HasGenericParam", ("test::extract", 1, "B")),
            Fact("FormalArg", ("test::extract", 0, "mixed", "&mut Mixed<A, B>")),
            Fact("StructPhantomTypeParam", ("Mixed", 0, "T")),  # Only first param is phantom
        ]

        result = detect_phantom_type_bindings("test::extract", facts)

        assert len(result) == 1
        assert result[0].args == ("test::extract", "A", "Mixed", "mixed")

    def test_no_phantom_types(self):
        """
        struct Pool<T> { ... }  // Non-phantom
        fun withdraw<P>(pool: &mut Pool<P>) { ... }
        -> No TypeBoundByPhantom facts
        """
        facts = [
            Fact("HasGenericParam", ("test::withdraw", 0, "P")),
            Fact("FormalArg", ("test::withdraw", 0, "pool", "&mut Pool<P>")),
            # No StructPhantomTypeParam facts
        ]

        result = detect_phantom_type_bindings("test::withdraw", facts)

        assert len(result) == 0

    def test_no_generic_params(self):
        """
        Function without generic params -> No bindings
        """
        facts = [
            Fact("FormalArg", ("test::foo", 0, "x", "u64")),
        ]

        result = detect_phantom_type_bindings("test::foo", facts)

        assert len(result) == 0

    def test_fqn_struct_name(self):
        """
        struct module::Pool<phantom T> { ... }
        fun withdraw<P>(pool: &mut module::Pool<P>) { ... }
        -> TypeBoundByPhantom with FQN
        """
        facts = [
            Fact("HasGenericParam", ("test::withdraw", 0, "P")),
            Fact("FormalArg", ("test::withdraw", 0, "pool", "&mut module::Pool<P>")),
            Fact("StructPhantomTypeParam", ("module::Pool", 0, "T")),
        ]

        result = detect_phantom_type_bindings("test::withdraw", facts)

        assert len(result) == 1
        assert result[0].args == ("test::withdraw", "P", "module::Pool", "pool")


class TestDetectExtractedValueReturned:
    """Test detection of safe patterns where extracted value is returned."""

    def test_direct_extraction_returned(self):
        """
        fun extract<T>(balance: &mut Balance<T>): Coin<T> {
            coin::take(balance, amount, ctx)  // returned, not transferred
        }
        -> ExtractedValueReturned(extract, T)
        """
        facts = [
            Fact("HasGenericParam", ("test::extract", 0, "T")),
            Fact("FunReturnType", ("test::extract", "Coin<T>")),
            Fact("AmountExtractionSink", ("test::extract", "stmt_1", "sui::coin::take")),
            Fact("CallResult", ("test::extract", "stmt_1", "result", "coin::take")),
            Fact("GenericCallArg", ("test::extract", "stmt_1", "sui::coin::take", 0, "T")),
            # No SinkUsesVar with role="transfer_value" -> not transferred
        ]

        result = detect_extracted_value_returned("test::extract", facts)

        assert len(result) == 1
        assert result[0].name == "ExtractedValueReturned"
        assert result[0].args == ("test::extract", "T")

    def test_extraction_transferred_not_safe(self):
        """
        fun withdraw<T>(balance: &mut Balance<T>) {
            let coin = coin::take(balance, amount, ctx);
            transfer::public_transfer(coin, sender);  // transferred, not returned
        }
        -> No ExtractedValueReturned
        """
        facts = [
            Fact("HasGenericParam", ("test::withdraw", 0, "T")),
            Fact("FunReturnType", ("test::withdraw", "()")),
            Fact("AmountExtractionSink", ("test::withdraw", "stmt_1", "sui::coin::take")),
            Fact("CallResult", ("test::withdraw", "stmt_1", "coin", "coin::take")),
            Fact("GenericCallArg", ("test::withdraw", "stmt_1", "sui::coin::take", 0, "T")),
            # Transferred to sink
            Fact("SinkUsesVar", ("test::withdraw", "stmt_2", "coin", "transfer_value")),
        ]

        result = detect_extracted_value_returned("test::withdraw", facts)

        assert len(result) == 0

    def test_ipa_wrapper_returned(self):
        """
        fun split_to_balance<T>(coin: Coin<T>): Balance<T> {
            let split = coin::split(...);
            transfer::public_transfer(coin, sender);  // original transferred
            coin::into_balance(split)  // extracted part returned
        }

        Pattern: Function returns Coin/Balance with no transfer of extracted value.
        -> ExtractedValueReturned(split_to_balance, T)
        """
        facts = [
            Fact("HasGenericParam", ("test::split_to_balance", 0, "T")),
            Fact("FunReturnType", ("test::split_to_balance", "Balance<T>")),
            Fact("AmountExtractionSink", ("test::split_to_balance", "stmt_1", "sui::coin::split")),
            Fact("CallResult", ("test::split_to_balance", "stmt_1", "split", "coin::split")),
            Fact("GenericCallArg", ("test::split_to_balance", "stmt_1", "sui::coin::split", 0, "T")),
            # Original coin transferred, but extraction result "split" is NOT
            Fact("SinkUsesVar", ("test::split_to_balance", "stmt_2", "coin", "transfer_value")),
        ]

        result = detect_extracted_value_returned("test::split_to_balance", facts)

        assert len(result) == 1
        assert result[0].name == "ExtractedValueReturned"
        assert result[0].args == ("test::split_to_balance", "T")

    def test_no_generic_params(self):
        """Function without generic params -> No facts."""
        facts = [
            Fact("FunReturnType", ("test::foo", "u64")),
        ]

        result = detect_extracted_value_returned("test::foo", facts)

        assert len(result) == 0

    def test_multiple_type_params(self):
        """
        fun swap<A, B>(coin_a: Coin<A>, coin_b: Coin<B>): (Coin<A>, Coin<B>) {
            let split_a = coin::split(&mut coin_a, ...);
            let split_b = coin::split(&mut coin_b, ...);
            transfer(coin_a, sender);
            transfer(coin_b, sender);
            (split_a, split_b)  // both returned
        }
        -> ExtractedValueReturned for both A and B
        """
        facts = [
            Fact("HasGenericParam", ("test::swap", 0, "A")),
            Fact("HasGenericParam", ("test::swap", 1, "B")),
            Fact("FunReturnType", ("test::swap", "(Coin<A>, Coin<B>)")),
            # Extractions
            Fact("AmountExtractionSink", ("test::swap", "stmt_1", "sui::coin::split")),
            Fact("CallResult", ("test::swap", "stmt_1", "split_a", "coin::split")),
            Fact("GenericCallArg", ("test::swap", "stmt_1", "sui::coin::split", 0, "A")),
            Fact("AmountExtractionSink", ("test::swap", "stmt_2", "sui::coin::split")),
            Fact("CallResult", ("test::swap", "stmt_2", "split_b", "coin::split")),
            Fact("GenericCallArg", ("test::swap", "stmt_2", "sui::coin::split", 0, "B")),
            # Originals transferred, not extracted parts
            Fact("SinkUsesVar", ("test::swap", "stmt_3", "coin_a", "transfer_value")),
            Fact("SinkUsesVar", ("test::swap", "stmt_4", "coin_b", "transfer_value")),
        ]

        result = detect_extracted_value_returned("test::swap", facts)

        assert len(result) == 2
        assert any(f.args == ("test::swap", "A") for f in result)
        assert any(f.args == ("test::swap", "B") for f in result)

import textwrap

from move.parse import build_code_facts, parse_move_source


def _has_fact(facts, name, args):
    return any(f.name == name and f.args == args for f in facts)


def test_fun_modifiers_generate_expected_facts():
    source = textwrap.dedent(
        """
        module ac1::config {
            fun plain() {}
            entry fun entry_only() {}
            public fun public_only() {}
            public entry fun public_entry() {}
        }
        """
    )

    root = parse_move_source(source)
    facts, _locations = build_code_facts(source, root)

    # Helper to qualify function name the same way parser does
    def q(name: str) -> str:
        return f"ac1::config::{name}"

    # 1. plain fun -> only Fun, no IsPublic / IsEntry
    assert _has_fact(facts, "Fun", (q("plain"),))
    assert not _has_fact(facts, "IsPublic", (q("plain"),))
    assert not _has_fact(facts, "IsEntry", (q("plain"),))

    # 2. entry fun -> Fun + IsEntry only
    assert _has_fact(facts, "Fun", (q("entry_only"),))
    assert not _has_fact(facts, "IsPublic", (q("entry_only"),))
    assert _has_fact(facts, "IsEntry", (q("entry_only"),))

    # 3. public fun -> Fun + IsPublic only
    assert _has_fact(facts, "Fun", (q("public_only"),))
    assert _has_fact(facts, "IsPublic", (q("public_only"),))
    assert not _has_fact(facts, "IsEntry", (q("public_only"),))

    # 4. public entry fun -> Fun + IsPublic + IsEntry
    assert _has_fact(facts, "Fun", (q("public_entry"),))
    assert _has_fact(facts, "IsPublic", (q("public_entry"),))
    assert _has_fact(facts, "IsEntry", (q("public_entry"),))


def test_function_name_not_parameter_name():
    """
    Regression test: Ensure we extract the function name, not the first parameter name.

    This was a bug where `public entry fun f(ctx: &mut TxContext)` would be parsed
    as function name "ctx" instead of "f".
    """
    source = textwrap.dedent(
        """
        module test::coin_vuln;

        public entry fun f(ctx: &mut TxContext) {
            // body
        }

        public fun another_func(admin: &AdminCap) {
            // body
        }
        """
    )

    root = parse_move_source(source)
    facts, _locations = build_code_facts(source, root)

    # The function names should be 'f' and 'another_func', NOT the parameter names
    assert _has_fact(facts, "Fun", ("test::coin_vuln::f",))
    assert not _has_fact(facts, "Fun", ("test::coin_vuln::ctx",))

    assert _has_fact(facts, "Fun", ("test::coin_vuln::another_func",))
    assert not _has_fact(facts, "Fun", ("test::coin_vuln::admin",))


def test_function_names_with_generics():
    source = textwrap.dedent(
        """
        module ac1::withdraw;

        public fun create_vault<CoinType>(ctx: &mut TxContext) {
            // body
        }

        public entry fun withdraw_safe<CoinType>(
            admin: &AdminCap,
            vault: &mut RewarderGlobalVault<CoinType>,
            amount: u64,
            ctx: &mut TxContext,
        ) {
            // body
        }

        fun balance_of<T>(vault: &Vault<T>): u64 {
            // body
        }
        """
    )

    root = parse_move_source(source)
    facts, _locations = build_code_facts(source, root)

    # Function names should be extracted correctly, NOT the generic type parameters
    assert _has_fact(facts, "Fun", ("ac1::withdraw::create_vault",))
    assert not _has_fact(facts, "Fun", ("ac1::withdraw::CoinType",))

    assert _has_fact(facts, "Fun", ("ac1::withdraw::withdraw_safe",))
    assert _has_fact(facts, "IsPublic", ("ac1::withdraw::withdraw_safe",))
    assert _has_fact(facts, "IsEntry", ("ac1::withdraw::withdraw_safe",))

    assert _has_fact(facts, "Fun", ("ac1::withdraw::balance_of",))
    assert not _has_fact(facts, "Fun", ("ac1::withdraw::T",))


def test_scoped_calls_with_nested_scoped_arguments():
    source = textwrap.dedent(
        """
        module test::coin_vuln;
        use sui::transfer;
        use sui::tx_context::{Self, TxContext};
        use sui::object::{Self, UID};

        public struct Cap has key {
            id: UID,
        }

        public entry fun f(ctx: &mut TxContext) {
            let cap = Cap { id: object::new(ctx) };
            transfer::transfer(cap, tx_context::sender(ctx));
        }
        """
    )
    root = parse_move_source(source)
    facts, _locations = build_code_facts(source, root)
    assert _has_fact(facts, "Call", ("sui::object::new@1",))
    assert _has_fact(facts, "Call", ("sui::transfer::transfer@2",))
    assert _has_fact(facts, "Call", ("sui::tx_context::sender@3",))


def test_returns_coin_type_fact():
    """Test that ReturnsCoinType fact is generated for functions returning Coin/Balance/Token."""
    source = textwrap.dedent(
        """
        module test::value_extraction;
        use sui::coin::Coin;
        use sui::balance::Balance;

        public fun withdraw_coin<T>(vault: &mut Vault<T>, amount: u64): Coin<T> {
            // extracts coin
        }

        public fun get_balance<T>(vault: &Vault<T>): Balance<T> {
            // returns balance
        }

        public fun get_amount(vault: &Vault): u64 {
            // returns primitive, not coin type
        }

        public fun get_ref<T>(vault: &Vault<T>): &Coin<T> {
            // returns reference to coin
        }
        """
    )

    root = parse_move_source(source)
    facts, _locations = build_code_facts(source, root)

    def q(name: str) -> str:
        return f"test::value_extraction::{name}"

    # Functions returning Coin/Balance should have ReturnsCoinType (stores full type with generics, FQN)
    assert _has_fact(facts, "ReturnsCoinType", (q("withdraw_coin"), "sui::coin::Coin<T>"))
    assert _has_fact(facts, "ReturnsCoinType", (q("get_balance"), "sui::balance::Balance<T>"))

    # Function returning u64 should NOT have ReturnsCoinType
    assert not any(f.name == "ReturnsCoinType" and f.args[0] == q("get_amount") for f in facts)

    # Function returning &Coin should NOT have ReturnsCoinType (immutable ref is safe)
    assert not any(f.name == "ReturnsCoinType" and f.args[0] == q("get_ref") for f in facts)


def test_has_generic_param_fact():
    """Test that HasGenericParam fact is generated for functions with type parameters."""
    source = textwrap.dedent(
        """
        module test::generics;

        public fun no_generics(x: u64): u64 { x }

        public fun single_generic<T>(val: T): T { val }

        public fun multi_generic<T, U>(a: T, b: U): T { a }

        public fun withdraw<CoinType>(pool: &mut Pool, amount: u64): Coin<CoinType> {
            // generic coin withdrawal
        }
        """
    )

    root = parse_move_source(source)
    facts, _locations = build_code_facts(source, root)

    def q(name: str) -> str:
        return f"test::generics::{name}"

    # no_generics should NOT have HasGenericParam
    assert not any(f.name == "HasGenericParam" and f.args[0] == q("no_generics") for f in facts)

    # single_generic<T> should have HasGenericParam(func, 0, "T")
    assert _has_fact(facts, "HasGenericParam", (q("single_generic"), 0, "T"))

    # multi_generic<T, U> should have two HasGenericParam facts
    assert _has_fact(facts, "HasGenericParam", (q("multi_generic"), 0, "T"))
    assert _has_fact(facts, "HasGenericParam", (q("multi_generic"), 1, "U"))

    # withdraw<CoinType> should have HasGenericParam(func, 0, "CoinType")
    assert _has_fact(facts, "HasGenericParam", (q("withdraw"), 0, "CoinType"))

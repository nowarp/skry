"""
Unit tests for parser validation - ensuring no ERROR nodes in AST.
"""
import textwrap
from move.parse import parse_move_source
from move.parse import find_error_nodes


def test_parser_no_errors_basic_module():
    """Test that a basic module parses without ERROR nodes."""
    source = textwrap.dedent(
        """
        module test::example {
            public fun hello() {}
        }
        """
    )

    root = parse_move_source(source)
    errors = []
    find_error_nodes(root, source, errors)

    assert len(errors) == 0, f"Found {len(errors)} ERROR nodes: {errors}"


def test_parser_no_errors_with_const():
    """Test that const declarations parse correctly."""
    source = textwrap.dedent(
        """
        module test::example {
            const OVERFLOW: u64 = 0;
            const DIVISION_BY_ZERO: u64 = 1;

            public fun test() {}
        }
        """
    )

    root = parse_move_source(source)
    errors = []
    find_error_nodes(root, source, errors)

    assert len(errors) == 0, f"Found {len(errors)} ERROR nodes: {errors}"


def test_parser_no_errors_with_attributes():
    """Test that attributes parse correctly."""
    source = textwrap.dedent(
        """
        module test::example {
            #[deprecated]
            public fun old_function() {}
        }
        """
    )

    root = parse_move_source(source)
    errors = []
    find_error_nodes(root, source, errors)

    assert len(errors) == 0, f"Found {len(errors)} ERROR nodes: {errors}"


def test_parser_no_errors_with_else():
    """Test that else clauses parse correctly."""
    source = textwrap.dedent(
        """
        module test::example {
            public fun test(x: u64): u64 {
                if (x > 0) {
                    return x;
                } else {
                    return 0;
                }
            }
        }
        """
    )

    root = parse_move_source(source)
    errors = []
    find_error_nodes(root, source, errors)

    assert len(errors) == 0, f"Found {len(errors)} ERROR nodes: {errors}"


def test_parser_no_errors_with_tuple_types():
    """Test that tuple types parse correctly."""
    source = textwrap.dedent(
        """
        module test::example {
            public fun test(): (u64, u64) {
                return (1, 2);
            }
        }
        """
    )

    root = parse_move_source(source)
    errors = []
    find_error_nodes(root, source, errors)

    assert len(errors) == 0, f"Found {len(errors)} ERROR nodes: {errors}"


def test_parser_no_errors_with_struct_expression():
    """Test that struct expressions parse correctly."""
    source = textwrap.dedent(
        """
        module test::example {
            struct I128 { bits: u128 }

            public fun create(): I128 {
                I128 { bits: 0 }
            }
        }
        """
    )

    root = parse_move_source(source)
    errors = []
    find_error_nodes(root, source, errors)

    assert len(errors) == 0, f"Found {len(errors)} ERROR nodes: {errors}"


def test_parser_no_errors_with_generic_function_calls():
    """Test that generic function calls parse correctly."""
    source = textwrap.dedent(
        """
        module test::example {
            public fun test<T>() {}

            public fun caller() {
                test<u64>();
            }
        }
        """
    )

    root = parse_move_source(source)
    errors = []
    find_error_nodes(root, source, errors)

    assert len(errors) == 0, f"Found {len(errors)} ERROR nodes: {errors}"


def test_parser_no_errors_with_nested_generics():
    """Test that nested generic types parse correctly."""
    source = textwrap.dedent(
        """
        module test::example {
            struct Coin<T> { value: T }

            public fun test(): Coin<Coin<u64>> {
                Coin<Coin<u64>> { value: Coin<u64> { value: 0 } }
            }
        }
        """
    )

    root = parse_move_source(source)
    errors = []
    find_error_nodes(root, source, errors)

    assert len(errors) == 0, f"Found {len(errors)} ERROR nodes: {errors}"


def test_parser_no_errors_else_with_expression():
    """Test that else clauses with expressions parse correctly."""
    source = textwrap.dedent(
        """
        module test::example {
            public fun test(x: u64): u64 {
                if (x > 0) {
                    x
                } else {
                    0
                }
            }
        }
        """
    )

    root = parse_move_source(source)
    errors = []
    find_error_nodes(root, source, errors)

    assert len(errors) == 0, f"Found {len(errors)} ERROR nodes: {errors}"


def test_parser_no_errors_field_access():
    """Test that field access expressions parse correctly."""
    source = textwrap.dedent(
        """
        module test::example {
            struct I128 { bits: u128 }

            public fun get_bits(x: I128): u128 {
                x.bits
            }
        }
        """
    )

    root = parse_move_source(source)
    errors = []
    find_error_nodes(root, source, errors)

    assert len(errors) == 0, f"Found {len(errors)} ERROR nodes: {errors}"



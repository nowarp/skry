"""Tests for struct and docstring extraction."""
import textwrap

from move.parse import parse_move_source
from move.extract import extract_struct_source, extract_function_source, extract_function_docstring


class TestExtractStructSource:
    """Test extract_struct_source function."""

    def test_extract_simple_struct(self):
        """Should extract a simple struct with fields."""
        source = textwrap.dedent("""
            module test::example {
                struct MyStruct has key, store {
                    id: UID,
                    value: u64,
                }

                public fun foo() {}
            }
        """)
        root = parse_move_source(source)
        result = extract_struct_source(source, "MyStruct", root)

        assert result is not None
        assert "struct MyStruct" in result
        assert "has key, store" in result
        assert "id: UID" in result
        assert "value: u64" in result

    def test_extract_struct_with_phantom_type(self):
        """Should extract struct with phantom type parameter."""
        source = textwrap.dedent("""
            module bucket_framework::vesting_lock {
                struct VestingLock<phantom T> has key, store {
                    id: UID,
                    vault: Balance<T>,
                    start_time: u64,
                    duration: u64,
                    released_amount: u64,
                }
            }
        """)
        root = parse_move_source(source)
        result = extract_struct_source(source, "VestingLock", root)

        assert result is not None
        assert "struct VestingLock<phantom T>" in result
        assert "has key, store" in result
        assert "vault: Balance<T>" in result

    def test_extract_struct_fully_qualified_name(self):
        """Should handle fully-qualified struct names."""
        source = textwrap.dedent("""
            module test::module {
                struct Config has key {
                    admin: address,
                }
            }
        """)
        root = parse_move_source(source)
        # Should work with fully-qualified name
        result = extract_struct_source(source, "test::module::Config", root)

        assert result is not None
        assert "struct Config" in result
        assert "admin: address" in result

    def test_extract_struct_not_found(self):
        """Should return None for non-existent struct."""
        source = textwrap.dedent("""
            module test::example {
                struct ExistingStruct has key {
                    id: UID,
                }
            }
        """)
        root = parse_move_source(source)
        result = extract_struct_source(source, "NonExistent", root)

        assert result is None

    def test_extract_capability_struct(self):
        """Should extract capability-like structs (single UID field)."""
        source = textwrap.dedent("""
            module test::admin {
                struct AdminCap has key {
                    id: UID,
                }

                struct OwnerCap has key, store {
                    id: UID,
                }
            }
        """)
        root = parse_move_source(source)

        admin_cap = extract_struct_source(source, "AdminCap", root)
        assert admin_cap is not None
        assert "struct AdminCap has key" in admin_cap
        assert "id: UID" in admin_cap

        owner_cap = extract_struct_source(source, "OwnerCap", root)
        assert owner_cap is not None
        assert "struct OwnerCap has key, store" in owner_cap

    def test_extract_multiple_structs_same_file(self):
        """Should extract correct struct when multiple exist."""
        source = textwrap.dedent("""
            module test::multi {
                struct First has key {
                    first_field: u64,
                }

                struct Second has store {
                    second_field: bool,
                }

                struct Third has key, store {
                    third_field: address,
                }
            }
        """)
        root = parse_move_source(source)

        first = extract_struct_source(source, "First", root)
        assert first is not None
        assert "first_field: u64" in first
        assert "second_field" not in first

        second = extract_struct_source(source, "Second", root)
        assert second is not None
        assert "second_field: bool" in second
        assert "first_field" not in second

        third = extract_struct_source(source, "Third", root)
        assert third is not None
        assert "third_field: address" in third

    def test_extract_struct_with_complex_types(self):
        """Should handle structs with complex nested types."""
        source = textwrap.dedent("""
            module test::complex {
                struct Vault<phantom T> has key {
                    id: UID,
                    balance: Balance<T>,
                    owner: address,
                    config: Option<Config>,
                    history: vector<Transaction>,
                }
            }
        """)
        root = parse_move_source(source)
        result = extract_struct_source(source, "Vault", root)

        assert result is not None
        assert "Balance<T>" in result
        assert "Option<Config>" in result
        assert "vector<Transaction>" in result


class TestExtractFunctionSourceComparison:
    """Compare struct and function extraction work similarly."""

    def test_both_extractions_work_together(self):
        """Both function and struct extraction should work on same source."""
        source = textwrap.dedent("""
            module test::combined {
                struct MyData has key {
                    id: UID,
                    value: u64,
                }

                public entry fun process(data: &mut MyData, amount: u64) {
                    data.value = data.value + amount;
                }
            }
        """)
        root = parse_move_source(source)

        struct_src = extract_struct_source(source, "MyData", root)
        func_src = extract_function_source(source, "process", root)

        assert struct_src is not None
        assert func_src is not None

        assert "struct MyData" in struct_src
        assert "id: UID" in struct_src

        assert "public entry fun process" in func_src
        assert "data.value" in func_src


class TestExtractFunctionDocstring:
    """Test extract_function_docstring function."""

    def test_extract_single_line_comment(self):
        """Should extract /// style docstrings."""
        source = textwrap.dedent("""
            module test::example {
                /// Withdraws funds from the vault
                public entry fun withdraw(vault: &mut Vault) {
                    // implementation
                }
            }
        """)
        root = parse_move_source(source)
        result = extract_function_docstring(source, "withdraw", root)

        assert result is not None
        assert "Withdraws funds from the vault" in result

    def test_extract_multiple_line_comments(self):
        """Should extract multiple /// lines."""
        source = textwrap.dedent("""
            module test::example {
                /// Transfers escrowed object to the recipient.
                /// Only the sender (owner of escrow) can call this.
                /// @param escrow - The escrow object to release
                public entry fun transfer(escrow: Escrow) {
                    // implementation
                }
            }
        """)
        root = parse_move_source(source)
        result = extract_function_docstring(source, "transfer", root)

        assert result is not None
        assert "Transfers escrowed object" in result
        assert "Only the sender" in result
        assert "@param escrow" in result

    def test_extract_block_comment(self):
        """Should extract /* */ style docstrings."""
        source = textwrap.dedent("""
            module test::example {
                /* Admin only function to update config */
                public entry fun update_config(admin: &AdminCap) {
                    // implementation
                }
            }
        """)
        root = parse_move_source(source)
        result = extract_function_docstring(source, "update_config", root)

        assert result is not None
        assert "Admin only" in result

    def test_no_docstring(self):
        """Should return None when no docstring exists."""
        source = textwrap.dedent("""
            module test::example {
                public entry fun no_docs() {
                    // implementation
                }
            }
        """)
        root = parse_move_source(source)
        result = extract_function_docstring(source, "no_docs", root)

        assert result is None

    def test_skip_annotations(self):
        """Should skip annotations and get docstring before them."""
        source = textwrap.dedent("""
            module test::example {
                /// This is a test helper function
                #[test_only]
                public fun test_helper() {
                    // implementation
                }
            }
        """)
        root = parse_move_source(source)
        result = extract_function_docstring(source, "test_helper", root)

        assert result is not None
        assert "test helper function" in result

    def test_docstring_not_from_previous_function(self):
        """Should not grab comments from previous function."""
        source = textwrap.dedent("""
            module test::example {
                /// First function docs
                public fun first() {}

                public fun second() {}
            }
        """)
        root = parse_move_source(source)
        result = extract_function_docstring(source, "second", root)

        # second has no docstring - first's docstring belongs to first
        assert result is None

    def test_fully_qualified_name(self):
        """Should work with fully-qualified function names."""
        source = textwrap.dedent("""
            module test::mymodule {
                /// Important security note here
                public entry fun secure_transfer() {}
            }
        """)
        root = parse_move_source(source)
        result = extract_function_docstring(source, "test::mymodule::secure_transfer", root)

        assert result is not None
        assert "Important security note" in result

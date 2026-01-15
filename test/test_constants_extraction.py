"""Tests for constant extraction from Move source code."""
from test_utils import parse_move, get_facts


class TestConstantExtraction:
    """Test extraction of const definitions into ConstDef facts."""

    def test_numeric_constant_u64(self):
        """Extract a simple u64 constant."""
        source = """
        module test::oracle {
            const MAX_SECONDS_OLD: u64 = 7200;
        }
        """
        _, facts, _ = parse_move(source)
        const_facts = get_facts(facts, "ConstDef")
        assert len(const_facts) == 1
        # ConstDef(qualified_name, simple_name, parsed_value, type)
        assert const_facts[0].args[0] == "test::oracle::MAX_SECONDS_OLD"
        assert const_facts[0].args[1] == "MAX_SECONDS_OLD"
        assert const_facts[0].args[2] == 7200  # parsed as int
        assert const_facts[0].args[3] == "u64"

    def test_numeric_constant_u8(self):
        """Extract a u8 constant."""
        source = """
        module test::config {
            const VERSION: u8 = 1;
        }
        """
        _, facts, _ = parse_move(source)
        const_facts = get_facts(facts, "ConstDef")
        assert len(const_facts) == 1
        assert const_facts[0].args[2] == 1
        assert const_facts[0].args[3] == "u8"

    def test_numeric_constant_with_underscores(self):
        """Handle Move numeric literals with underscores."""
        source = """
        module test::config {
            const BIG_NUMBER: u64 = 1_000_000;
        }
        """
        _, facts, _ = parse_move(source)
        const_facts = get_facts(facts, "ConstDef")
        assert len(const_facts) == 1
        assert const_facts[0].args[2] == 1000000

    def test_bool_constant_true(self):
        """Extract a boolean constant (true)."""
        source = """
        module test::config {
            const ENABLED: bool = true;
        }
        """
        _, facts, _ = parse_move(source)
        const_facts = get_facts(facts, "ConstDef")
        assert len(const_facts) == 1
        assert const_facts[0].args[2] is True
        assert const_facts[0].args[3] == "bool"

    def test_bool_constant_false(self):
        """Extract a boolean constant (false)."""
        source = """
        module test::config {
            const PAUSED: bool = false;
        }
        """
        _, facts, _ = parse_move(source)
        const_facts = get_facts(facts, "ConstDef")
        assert len(const_facts) == 1
        assert const_facts[0].args[2] is False

    def test_address_constant(self):
        """Extract an address constant."""
        source = """
        module test::config {
            const ADMIN: address = @0x1;
        }
        """
        _, facts, _ = parse_move(source)
        const_facts = get_facts(facts, "ConstDef")
        assert len(const_facts) == 1
        assert const_facts[0].args[2] == "@0x1"
        assert const_facts[0].args[3] == "address"

    def test_multiple_constants(self):
        """Extract multiple constants from a module."""
        source = """
        module test::config {
            const MIN_VALUE: u64 = 100;
            const MAX_VALUE: u64 = 10000;
            const ENABLED: bool = true;
        }
        """
        _, facts, _ = parse_move(source)
        const_facts = get_facts(facts, "ConstDef")
        assert len(const_facts) == 3

        # Check that all constants were extracted
        names = [f.args[1] for f in const_facts]
        assert "MIN_VALUE" in names
        assert "MAX_VALUE" in names
        assert "ENABLED" in names

    def test_constant_with_module_qualification(self):
        """Constant names are qualified with module path."""
        source = """
        module pyth::oracle {
            const PYTH_MAX_SECONDS_OLD: u64 = 7200;
        }
        """
        _, facts, _ = parse_move(source)
        const_facts = get_facts(facts, "ConstDef")
        assert len(const_facts) == 1
        # First arg should be fully qualified
        assert const_facts[0].args[0] == "pyth::oracle::PYTH_MAX_SECONDS_OLD"
        # Second arg should be simple name
        assert const_facts[0].args[1] == "PYTH_MAX_SECONDS_OLD"

    def test_constant_location_tracking(self):
        """Constants should have source locations tracked."""
        source = """
        module test::config {
            const MAGIC: u64 = 42;
        }
        """
        _, facts, location_map = parse_move(source)
        const_facts = get_facts(facts, "ConstDef")
        assert len(const_facts) == 1
        qualified_name = const_facts[0].args[0]
        assert qualified_name in location_map

    def test_no_constants(self):
        """Module with no constants produces no ConstDef facts."""
        source = """
        module test::empty {
            public fun hello() {}
        }
        """
        _, facts, _ = parse_move(source)
        const_facts = get_facts(facts, "ConstDef")
        assert len(const_facts) == 0

    def test_pyth_oracle_pattern(self):
        """Test the ORA-1 pattern: Pyth oracle staleness window."""
        source = """
        module lending::oracle {
            use pyth::price_info::PriceInfoObject;

            const PYTH_MAX_SECONDS_OLD: u64 = 7200;

            public fun get_price(price_info: &PriceInfoObject): u64 {
                // Uses PYTH_MAX_SECONDS_OLD for staleness check
                42
            }
        }
        """
        _, facts, _ = parse_move(source)
        const_facts = get_facts(facts, "ConstDef")

        # Find the PYTH constant
        pyth_consts = [f for f in const_facts if "PYTH" in f.args[1]]
        assert len(pyth_consts) == 1

        # Value should be parsed as integer
        assert pyth_consts[0].args[2] == 7200

        # Can use this for detecting ORA-1: value > reasonable threshold (e.g., 300)
        assert pyth_consts[0].args[2] > 300


class TestConstantIntegration:
    """Integration tests for constants with other facts."""

    def test_constants_alongside_functions(self):
        """Constants and functions coexist properly."""
        source = """
        module test::mixed {
            const THRESHOLD: u64 = 100;

            public fun check(value: u64): bool {
                value > THRESHOLD
            }
        }
        """
        _, facts, _ = parse_move(source)

        # Should have both constant and function facts
        const_facts = get_facts(facts, "ConstDef")
        fun_facts = get_facts(facts, "Fun")

        assert len(const_facts) == 1
        assert len(fun_facts) == 1

    def test_constants_alongside_structs(self):
        """Constants and structs coexist properly."""
        source = """
        module test::mixed {
            const VERSION: u8 = 1;

            struct Config has key {
                id: UID,
                version: u8
            }
        }
        """
        _, facts, _ = parse_move(source)

        const_facts = get_facts(facts, "ConstDef")
        struct_facts = get_facts(facts, "Struct")

        assert len(const_facts) == 1
        assert len(struct_facts) == 1

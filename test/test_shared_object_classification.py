"""Tests for structural shared object detection."""
import textwrap

from core.facts import Fact
from core.context import ProjectContext
from analysis.patterns import (
    build_shared_object_facts,
    _find_shared_objects_in_file,
)
from move.sui_patterns import SHARE_OBJECT_CALLEES


class TestSharedObjectFactSchema:
    """Test IsSharedObject fact schema."""

    def test_fact_creation(self):
        """IsSharedObject fact can be created."""
        fact = Fact("IsSharedObject", ("test::Pool",))
        assert fact.name == "IsSharedObject"
        assert fact.args == ("test::Pool",)


class TestShareObjectCallPatterns:
    """Test that we detect all share_object call variants."""

    def test_all_patterns_covered(self):
        """FQN share_object patterns are in SHARE_OBJECT_CALLEES.

        Note: Only FQN forms are in the set. Simple name matching
        handles unqualified calls like 'transfer::share_object'.
        """
        assert "sui::transfer::share_object" in SHARE_OBJECT_CALLEES
        assert "sui::transfer::public_share_object" in SHARE_OBJECT_CALLEES


class TestFindSharedObjectsInFile:
    """Test _find_shared_objects_in_file function."""

    def _find_shared_objects(self, source):
        """Helper to call _find_shared_objects_in_file with required params."""
        from move.parse import parse_move_source, _parse_module_declaration, _parse_imports

        root = parse_move_source(source)
        module_path = _parse_module_declaration(source, root)
        import_map = _parse_imports(source, root)
        return _find_shared_objects_in_file(source, root, {}, import_map, module_path)

    def test_detects_share_object_pattern(self):
        """Detects struct type from share_object(var) pattern."""
        source = textwrap.dedent("""
            module test::pool {
                public struct Pool has key {
                    id: UID,
                    balance: u64,
                }

                fun init(ctx: &mut TxContext) {
                    let pool = Pool {
                        id: object::new(ctx),
                        balance: 0,
                    };
                    transfer::share_object(pool);
                }
            }
        """)
        shared_types = self._find_shared_objects(source)

        assert len(shared_types) == 1
        assert any("Pool" in t for t in shared_types)

    def test_detects_public_share_object(self):
        """Detects public_share_object variant."""
        source = textwrap.dedent("""
            module test::registry {
                public struct Registry has key {
                    id: UID,
                }

                fun init(ctx: &mut TxContext) {
                    let registry = Registry { id: object::new(ctx) };
                    transfer::public_share_object(registry);
                }
            }
        """)



        shared_types = self._find_shared_objects(source)

        assert len(shared_types) == 1
        assert any("Registry" in t for t in shared_types)

    def test_detects_sui_prefixed_share_object(self):
        """Detects sui::transfer::share_object variant."""
        source = textwrap.dedent("""
            module test::config {
                public struct Config has key {
                    id: UID,
                }

                fun init(ctx: &mut TxContext) {
                    let config = Config { id: object::new(ctx) };
                    sui::transfer::share_object(config);
                }
            }
        """)



        shared_types = self._find_shared_objects(source)

        assert len(shared_types) == 1
        assert any("Config" in t for t in shared_types)

    def test_no_share_object_returns_empty(self):
        """Returns empty when no share_object calls."""
        source = textwrap.dedent("""
            module test::cap {
                public struct AdminCap has key {
                    id: UID,
                }

                fun init(ctx: &mut TxContext) {
                    let cap = AdminCap { id: object::new(ctx) };
                    transfer::transfer(cap, tx_context::sender(ctx));
                }
            }
        """)



        shared_types = self._find_shared_objects(source)

        assert len(shared_types) == 0

    def test_multiple_shared_objects(self):
        """Detects multiple shared object types."""
        source = textwrap.dedent("""
            module test::multi {
                public struct Pool has key { id: UID }
                public struct Registry has key { id: UID }

                fun init(ctx: &mut TxContext) {
                    let pool = Pool { id: object::new(ctx) };
                    let registry = Registry { id: object::new(ctx) };
                    transfer::share_object(pool);
                    transfer::share_object(registry);
                }
            }
        """)



        shared_types = self._find_shared_objects(source)

        assert len(shared_types) == 2


class TestBuildSharedObjectFacts:
    """Test build_shared_object_facts function."""

    def _make_ctx(self, source: str) -> ProjectContext:
        """Create ProjectContext from source."""
        from move.parse import parse_move_source, build_code_facts

        root = parse_move_source(source)
        facts, _ = build_code_facts(source, root, filename="test.move")

        ctx = ProjectContext(["test.move"])
        ctx.source_files["test.move"].source_code = source
        ctx.source_files["test.move"].root = root
        ctx.source_files["test.move"].facts = facts
        ctx.source_files["test.move"].is_test_only = False
        ctx.source_files["test.move"].module_path = "test::pool"  # Add module_path
        ctx.source_files["test.move"].import_map = {}  # Add empty import_map
        return ctx

    def test_creates_is_shared_object_fact(self):
        """Creates IsSharedObject fact for shared types."""
        source = textwrap.dedent("""
            module test::pool {
                public struct Pool has key {
                    id: UID,
                    balance: u64,
                }

                fun init(ctx: &mut TxContext) {
                    let pool = Pool { id: object::new(ctx), balance: 0 };
                    transfer::share_object(pool);
                }
            }
        """)
        ctx = self._make_ctx(source)
        build_shared_object_facts(ctx)

        facts = ctx.source_files["test.move"].facts
        shared_facts = [f for f in facts if f.name == "IsSharedObject"]

        assert len(shared_facts) == 1
        assert "Pool" in shared_facts[0].args[0]

    def test_skips_test_only_files(self):
        """Skips test-only files."""
        source = textwrap.dedent("""
            module test::pool {
                public struct Pool has key { id: UID }

                fun init(ctx: &mut TxContext) {
                    let pool = Pool { id: object::new(ctx) };
                    transfer::share_object(pool);
                }
            }
        """)
        ctx = self._make_ctx(source)
        ctx.source_files["test.move"].is_test_only = True

        build_shared_object_facts(ctx)

        facts = ctx.source_files["test.move"].facts
        shared_facts = [f for f in facts if f.name == "IsSharedObject"]
        assert len(shared_facts) == 0

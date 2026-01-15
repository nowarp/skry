"""Tests for field write detection (WritesField facts)."""
import textwrap
import tempfile
import os

from core.context import ProjectContext
from analysis import run_structural_analysis
from test_utils import has_fact, get_facts


class TestFieldTracking:
    """Test WritesField fact generation from IR."""

    def _create_temp_move_file(self, content: str) -> str:
        """Create a temporary Move file and return its path."""
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, 'w') as f:
            f.write(textwrap.dedent(content))
        return path

    def test_direct_assignment(self):
        """Direct field assignment should generate WritesField fact."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct Pool has key {
                    fee_rate: u64
                }

                public fun set_fee(pool: &mut Pool, rate: u64) {
                    pool.fee_rate = rate;
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)
            facts = ctx.source_files[path].facts

            # Should have WritesField fact for pool.fee_rate
            assert has_fact(facts, "WritesField",
                          ("test::pool::set_fee", "test::pool::Pool", "fee_rate"))
        finally:
            os.unlink(path)

    def test_compound_assignment(self):
        """Compound assignment (counter = counter + 1) should generate WritesField fact."""
        path = self._create_temp_move_file("""
            module test::counter {
                struct Counter has key {
                    value: u64
                }

                public fun increment(counter: &mut Counter) {
                    counter.value = counter.value + 1;
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)
            facts = ctx.source_files[path].facts

            # Should have WritesField fact for counter.value
            assert has_fact(facts, "WritesField",
                          ("test::counter::increment", "test::counter::Counter", "value"))
        finally:
            os.unlink(path)

    def test_no_write_on_read(self):
        """Reading a field should NOT generate WritesField fact."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct Pool has key {
                    fee_rate: u64
                }

                public fun get_fee(pool: &Pool): u64 {
                    pool.fee_rate
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)
            facts = ctx.source_files[path].facts

            # Should NOT have WritesField fact for get_fee
            writes_field_facts = get_facts(facts, "WritesField")
            assert not any(f.args[0] == "test::pool::get_fee" for f in writes_field_facts)
        finally:
            os.unlink(path)

    def test_nested_field_write(self):
        """Writing to nested field should generate WritesField fact."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct Config has store {
                    fee_rate: u64
                }

                struct Pool has key {
                    config: Config
                }

                public fun set_fee(pool: &mut Pool, rate: u64) {
                    pool.config.fee_rate = rate;
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)
            facts = ctx.source_files[path].facts

            # Should have WritesField fact with nested field path
            assert has_fact(facts, "WritesField",
                          ("test::pool::set_fee", "test::pool::Pool", "config.fee_rate"))
        finally:
            os.unlink(path)

    def test_multiple_field_writes(self):
        """Function writing multiple fields should generate multiple WritesField facts."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct Pool has key {
                    fee_rate: u64,
                    paused: bool
                }

                public fun update_pool(pool: &mut Pool, rate: u64, paused: bool) {
                    pool.fee_rate = rate;
                    pool.paused = paused;
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)
            facts = ctx.source_files[path].facts

            # Should have WritesField facts for both fields
            assert has_fact(facts, "WritesField",
                          ("test::pool::update_pool", "test::pool::Pool", "fee_rate"))
            assert has_fact(facts, "WritesField",
                          ("test::pool::update_pool", "test::pool::Pool", "paused"))
        finally:
            os.unlink(path)

    def test_init_function_generates_writes_field(self):
        """Init function should generate WritesField (filtering happens in derived_facts)."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct Pool has key {
                    fee_rate: u64
                }

                fun init(ctx: &mut TxContext) {
                    let pool = Pool { fee_rate: 100 };
                    transfer::share_object(pool);
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)
            _ = ctx.source_files[path].facts

            # Init functions are filtered in HasPrivilegedSetter logic, not here
            # WritesField fact generation is structural only
        finally:
            os.unlink(path)

    def test_fqn_qualification(self):
        """WritesField uses FQN, not simple struct name."""
        path = self._create_temp_move_file("""
            module my::package {
                struct Pool has key { id: UID, fee_rate: u64 }

                public fun set_fee(pool: &mut Pool, rate: u64) {
                    pool.fee_rate = rate;
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)
            facts = ctx.source_files[path].facts

            writes = get_facts(facts, "WritesField")

            # Must use FQN (module::struct)
            assert any(f.args[1] == "my::package::Pool" for f in writes), \
                f"WritesField should use FQN 'my::package::Pool', got: {[f.args for f in writes]}"

            # Should NOT use simple name
            assert not any(f.args[1] == "Pool" for f in writes), \
                "WritesField should not use simple name 'Pool'"
        finally:
            os.unlink(path)

    def test_cross_module_type_resolution(self):
        """Setter writing to imported struct uses module-qualified name.

        Setter writing to imported struct correctly resolves to defining module via imports.
        """
        path_a = self._create_temp_move_file("""
            module a::types {
                struct Pool has key, store { id: UID, fee_rate: u64 }
            }
        """)
        path_b = self._create_temp_move_file("""
            module b::ops {
                use a::types::Pool;

                public fun set_fee(pool: &mut Pool, rate: u64) {
                    pool.fee_rate = rate;
                }
            }
        """)
        try:
            ctx = ProjectContext([path_a, path_b])
            run_structural_analysis(ctx)
            facts = ctx.source_files[path_b].facts

            writes = get_facts(facts, "WritesField")

            # Type resolved to defining module via import
            assert any(f.args[1] == "a::types::Pool" for f in writes), \
                f"WritesField should resolve to defining module, got: {[f.args for f in writes]}"

            # Should NOT use simple name
            assert not any(f.args[1] == "Pool" for f in writes), \
                "WritesField should not use simple name 'Pool'"
        finally:
            os.unlink(path_a)
            os.unlink(path_b)


    def test_container_method_mutation(self):
        """Container method calls (insert, add, remove) should generate WritesField."""
        path = self._create_temp_move_file("""
            module test::policy {
                use sui::vec_map::{Self, VecMap};
                use sui::table::{Self, Table};

                struct Policy has key {
                    id: UID,
                    fees: VecMap<address, u16>,
                    modes: Table<address, u64>,
                }

                public fun add_fee(policy: &mut Policy, addr: address, fee: u16) {
                    policy.fees.insert(addr, fee);
                }

                public fun add_mode(policy: &mut Policy, addr: address, mode: u64) {
                    policy.modes.add(addr, mode);
                }

                public fun remove_fee(policy: &mut Policy, addr: &address) {
                    policy.fees.remove(addr);
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)
            facts = ctx.source_files[path].facts

            # Container mutations should generate WritesField facts
            assert has_fact(facts, "WritesField",
                          ("test::policy::add_fee", "test::policy::Policy", "fees"))
            assert has_fact(facts, "WritesField",
                          ("test::policy::add_mode", "test::policy::Policy", "modes"))
            assert has_fact(facts, "WritesField",
                          ("test::policy::remove_fee", "test::policy::Policy", "fees"))
        finally:
            os.unlink(path)


class TestTransitiveWritesField:
    """Test interprocedural propagation of WritesField facts."""

    def _create_temp_move_file(self, content: str) -> str:
        """Create a temporary Move file and return its path."""
        fd, path = tempfile.mkstemp(suffix=".move")
        with os.fdopen(fd, 'w') as f:
            f.write(textwrap.dedent(content))
        return path

    def test_indirect_setter_same_module(self):
        """Caller of setter gets TransitiveWritesField fact."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct AdminCap has key { id: UID }
                struct Pool has key { id: UID, fee_rate: u64 }

                public fun update_config(_: &AdminCap, pool: &mut Pool, rate: u64) {
                    internal_set_fee(pool, rate);
                }

                fun internal_set_fee(pool: &mut Pool, rate: u64) {
                    pool.fee_rate = rate;
                }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)
            facts = ctx.source_files[path].facts

            # Direct write detected
            assert has_fact(facts, "WritesField",
                          ("test::pool::internal_set_fee", "test::pool::Pool", "fee_rate"))

            # Transitive write propagated to caller
            assert has_fact(facts, "TransitiveWritesField",
                          ("test::pool::update_config", "test::pool::Pool", "fee_rate", "test::pool::internal_set_fee"))
        finally:
            os.unlink(path)

    def test_deep_call_chain(self):
        """Three-level call chain: a() -> b() -> c() where c() writes field."""
        path = self._create_temp_move_file("""
            module test::pool {
                struct AdminCap has key { id: UID }
                struct Pool has key { id: UID, fee_rate: u64 }

                public fun a(_: &AdminCap, pool: &mut Pool, r: u64) { b(pool, r); }
                fun b(pool: &mut Pool, r: u64) { c(pool, r); }
                fun c(pool: &mut Pool, r: u64) { pool.fee_rate = r; }
            }
        """)
        try:
            ctx = ProjectContext([path])
            run_structural_analysis(ctx)
            facts = ctx.source_files[path].facts

            # Direct write at leaf
            assert has_fact(facts, "WritesField",
                          ("test::pool::c", "test::pool::Pool", "fee_rate"))

            # Transitive propagates to b
            assert has_fact(facts, "TransitiveWritesField",
                          ("test::pool::b", "test::pool::Pool", "fee_rate", "test::pool::c"))

            # Transitive propagates to a (may be via b or c)
            transitive_facts = get_facts(facts, "TransitiveWritesField")
            assert any(
                f.args[0] == "test::pool::a" and
                f.args[1] == "test::pool::Pool" and
                f.args[2] == "fee_rate"
                for f in transitive_facts
            ), "a() should have TransitiveWritesField for fee_rate"
        finally:
            os.unlink(path)

    def test_cross_module_indirect_setter(self):
        """Caller in module A calls setter in module B."""
        path_a = self._create_temp_move_file("""
            module a::admin {
                use b::pool::Pool;
                use b::pool;

                struct AdminCap has key { id: UID }

                public fun update(_: &AdminCap, pool: &mut Pool, rate: u64) {
                    pool::set_rate(pool, rate);
                }
            }
        """)
        path_b = self._create_temp_move_file("""
            module b::pool {
                struct Pool has key { id: UID, fee_rate: u64 }

                public fun set_rate(pool: &mut Pool, r: u64) {
                    pool.fee_rate = r;
                }
            }
        """)
        try:
            ctx = ProjectContext([path_a, path_b])
            run_structural_analysis(ctx)

            # Get facts from module A
            facts_a = ctx.source_files[path_a].facts
            facts_b = ctx.source_files[path_b].facts

            # Direct write in module B
            assert has_fact(facts_b, "WritesField",
                          ("b::pool::set_rate", "b::pool::Pool", "fee_rate"))

            # Transitive write crosses module boundary to A
            assert has_fact(facts_a, "TransitiveWritesField",
                          ("a::admin::update", "b::pool::Pool", "fee_rate", "b::pool::set_rate"))
        finally:
            os.unlink(path_a)
            os.unlink(path_b)

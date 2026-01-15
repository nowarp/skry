"""
Tests for unused argument detection.

The unused argument lint detects function arguments that are never used
in the function body. This is a code quality issue that may indicate:
- Dead code / incomplete implementation
- Copy-paste errors
- Missing functionality
"""

from typing import List

from move.taint_facts import generate_unused_arg_facts
from move.ir import (
    Function,
    Param,
    LetStmt,
    ExprStmt,
    ReturnStmt,
    Call,
    VarRef,
    BinOp,
    Literal,
)
from core.facts import Fact


def sorted_facts(facts: List[Fact]) -> List[Fact]:
    return sorted(facts, key=lambda f: (f.name, f.args))


def assert_facts_equal(actual: List[Fact], expected: List[Fact]):
    assert sorted_facts(actual) == sorted_facts(expected), f"\nActual: {sorted_facts(actual)}\nExpected: {sorted_facts(expected)}"


class TestUnusedArgFactGeneration:
    """Tests for UnusedArg fact generation from IR."""

    def test_no_unused_args_when_all_used(self):
        """All arguments are used - should not generate UnusedArg facts."""
        func = Function(
            name="test::use_all",
            params=[
                Param(name="x", typ="u64", is_mut=False, idx=0),
                Param(name="y", typ="u64", is_mut=False, idx=1),
            ],
            ret_type="u64",
            body=[
                ReturnStmt(
                    id="s1", line=1,
                    value=BinOp(
                        id="e1", op="+",
                        left=VarRef(id="e2", name="x"),
                        right=VarRef(id="e3", name="y")
                    )
                )
            ],
            is_public=True,
            is_entry=False,
            line=1
        )

        facts = generate_unused_arg_facts(func)
        assert facts == [], f"Expected no UnusedArg facts, got: {facts}"

    def test_one_unused_arg(self):
        """One argument is unused - should generate one UnusedArg fact."""
        func = Function(
            name="test::use_one",
            params=[
                Param(name="x", typ="u64", is_mut=False, idx=0),
                Param(name="unused_y", typ="u64", is_mut=False, idx=1),
            ],
            ret_type="u64",
            body=[
                ReturnStmt(id="s1", line=1, value=VarRef(id="e1", name="x"))
            ],
            is_public=True,
            is_entry=False,
            line=1
        )

        facts = generate_unused_arg_facts(func)
        expected = [Fact("UnusedArg", ("test::use_one", "unused_y", 1))]
        assert_facts_equal(facts, expected)

    def test_all_unused_args(self):
        """All arguments are unused - should generate UnusedArg for each."""
        func = Function(
            name="test::use_none",
            params=[
                Param(name="x", typ="u64", is_mut=False, idx=0),
                Param(name="y", typ="u64", is_mut=False, idx=1),
            ],
            ret_type="u64",
            body=[
                ReturnStmt(id="s1", line=1, value=Literal(id="e1", value=0, kind="int"))
            ],
            is_public=True,
            is_entry=False,
            line=1
        )

        facts = generate_unused_arg_facts(func)
        expected = [
            Fact("UnusedArg", ("test::use_none", "x", 0)),
            Fact("UnusedArg", ("test::use_none", "y", 1)),
        ]
        assert_facts_equal(facts, expected)

    def test_arg_used_in_call(self):
        """Argument used as call argument - should not be marked unused."""
        func = Function(
            name="test::pass_arg",
            params=[
                Param(name="value", typ="u64", is_mut=False, idx=0),
            ],
            ret_type=None,
            body=[
                ExprStmt(
                    id="s1", line=1,
                    expr=Call(id="e1", callee="process", args=[VarRef(id="e2", name="value")])
                )
            ],
            is_public=True,
            is_entry=False,
            line=1
        )

        facts = generate_unused_arg_facts(func)
        assert facts == []

    def test_arg_used_in_let_rhs(self):
        """Argument used in let statement RHS - should not be marked unused."""
        func = Function(
            name="test::assign_arg",
            params=[
                Param(name="input", typ="u64", is_mut=False, idx=0),
            ],
            ret_type="u64",
            body=[
                LetStmt(id="s1", line=1, bindings=["copy"], value=VarRef(id="e1", name="input"), type_ann=None),
                ReturnStmt(id="s2", line=2, value=VarRef(id="e2", name="copy"))
            ],
            is_public=True,
            is_entry=False,
            line=1
        )

        facts = generate_unused_arg_facts(func)
        assert facts == []

    def test_no_params(self):
        """Function with no parameters - should not generate any facts."""
        func = Function(
            name="test::no_params",
            params=[],
            ret_type="u64",
            body=[
                ReturnStmt(id="s1", line=1, value=Literal(id="e1", value=42, kind="int"))
            ],
            is_public=True,
            is_entry=False,
            line=1
        )

        facts = generate_unused_arg_facts(func)
        assert facts == []

    def test_ctx_unused_in_public_entry_not_flagged(self):
        """TxContext in public entry function is NOT flagged (required by Sui runtime)."""
        func = Function(
            name="test::unused_ctx",
            params=[
                Param(name="value", typ="u64", is_mut=False, idx=0),
                Param(name="ctx", typ="&mut TxContext", is_mut=True, idx=1),
            ],
            ret_type="u64",
            body=[
                ReturnStmt(id="s1", line=1, value=VarRef(id="e1", name="value"))
            ],
            is_public=True,
            is_entry=True,
            line=1
        )

        facts = generate_unused_arg_facts(func)
        # TxContext in public entry functions is required by Sui runtime - not flagged
        assert facts == []

    def test_ctx_unused_in_non_entry_not_flagged(self):
        """TxContext is NEVER flagged (even in non-entry functions)."""
        func = Function(
            name="test::helper_with_ctx",
            params=[
                Param(name="value", typ="u64", is_mut=False, idx=0),
                Param(name="ctx", typ="&mut TxContext", is_mut=True, idx=1),
            ],
            ret_type="u64",
            body=[
                ReturnStmt(id="s1", line=1, value=VarRef(id="e1", name="value"))
            ],
            is_public=True,
            is_entry=False,  # Not entry!
            line=1
        )

        facts = generate_unused_arg_facts(func)
        # TxContext is never flagged - Sui runtime context passed for flexibility
        assert facts == []

    def test_init_function_skipped(self):
        """init functions are never checked for unused args."""
        func = Function(
            name="test::module::init",
            params=[
                Param(name="ctx", typ="&mut TxContext", is_mut=True, idx=0),
                Param(name="fee_wallet", typ="address", is_mut=False, idx=1),
                Param(name="decimals", typ="u8", is_mut=False, idx=2),
            ],
            ret_type=None,
            body=[],  # Empty body - all params unused
            is_public=True,
            is_entry=False,
            line=1
        )

        facts = generate_unused_arg_facts(func)
        # init functions are completely skipped
        assert facts == []

    def test_arg_used_in_binary_op(self):
        """Argument used in binary operation - should not be marked unused."""
        func = Function(
            name="test::compute",
            params=[
                Param(name="a", typ="u64", is_mut=False, idx=0),
                Param(name="b", typ="u64", is_mut=False, idx=1),
            ],
            ret_type="u64",
            body=[
                LetStmt(
                    id="s1", line=1, bindings=["result"],
                    value=BinOp(
                        id="e1", op="*",
                        left=VarRef(id="e2", name="a"),
                        right=Literal(id="e3", value=2, kind="int")
                    ),
                    type_ann=None
                ),
                ReturnStmt(id="s2", line=2, value=VarRef(id="e4", name="result"))
            ],
            is_public=True,
            is_entry=False,
            line=1
        )

        facts = generate_unused_arg_facts(func)
        expected = [Fact("UnusedArg", ("test::compute", "b", 1))]
        assert_facts_equal(facts, expected)


class TestUnusedArgSkipPatterns:
    """Tests for arguments that should be skipped."""

    def test_skip_underscore_prefix(self):
        """Arguments starting with _ should be skipped (intentionally unused)."""
        func = Function(
            name="test::skip_underscore",
            params=[
                Param(name="_unused", typ="u64", is_mut=False, idx=0),
                Param(name="used", typ="u64", is_mut=False, idx=1),
            ],
            ret_type="u64",
            body=[
                ReturnStmt(id="s1", line=1, value=VarRef(id="e1", name="used"))
            ],
            is_public=True,
            is_entry=False,
            line=1
        )

        facts = generate_unused_arg_facts(func)
        # _unused should NOT appear in results
        assert facts == []

    def test_skip_bare_underscore(self):
        """Argument named exactly '_' should be skipped."""
        func = Function(
            name="test::skip_bare_underscore",
            params=[
                Param(name="_", typ="u64", is_mut=False, idx=0),
            ],
            ret_type="u64",
            body=[
                ReturnStmt(id="s1", line=1, value=Literal(id="e1", value=42, kind="int"))
            ],
            is_public=True,
            is_entry=False,
            line=1
        )

        facts = generate_unused_arg_facts(func)
        assert facts == []

    def test_skip_role_type_argument(self):
        """Arguments with role types should be skipped (capability pattern)."""
        func = Function(
            name="test::skip_role_arg",
            params=[
                Param(name="admin_cap", typ="&AdminCap", is_mut=False, idx=0),
                Param(name="value", typ="u64", is_mut=False, idx=1),
            ],
            ret_type="u64",
            body=[
                ReturnStmt(id="s1", line=1, value=VarRef(id="e1", name="value"))
            ],
            is_public=True,
            is_entry=False,
            line=1
        )

        # Pass AdminCap as a role type
        role_types = {"AdminCap"}
        facts = generate_unused_arg_facts(func, role_types)
        # admin_cap should NOT appear in results
        assert facts == []

    def test_skip_qualified_role_type(self):
        """Role types with module path should be matched by simple name."""
        func = Function(
            name="test::skip_qualified_role",
            params=[
                Param(name="owner_cap", typ="&mut package::module::OwnerCap", is_mut=True, idx=0),
                Param(name="amount", typ="u64", is_mut=False, idx=1),
            ],
            ret_type=None,
            body=[
                ExprStmt(
                    id="s1", line=1,
                    expr=Call(id="e1", callee="do_something", args=[VarRef(id="e2", name="amount")])
                )
            ],
            is_public=True,
            is_entry=True,
            line=1
        )

        # OwnerCap is a role
        role_types = {"OwnerCap"}
        facts = generate_unused_arg_facts(func, role_types)
        # owner_cap should NOT appear in results
        assert facts == []

    def test_mixed_skip_and_report(self):
        """Mix of skippable and reportable unused args."""
        func = Function(
            name="test::mixed",
            params=[
                Param(name="_ignored", typ="u64", is_mut=False, idx=0),
                Param(name="admin", typ="&AdminCap", is_mut=False, idx=1),
                Param(name="unused_value", typ="u64", is_mut=False, idx=2),
                Param(name="used", typ="u64", is_mut=False, idx=3),
            ],
            ret_type="u64",
            body=[
                ReturnStmt(id="s1", line=1, value=VarRef(id="e1", name="used"))
            ],
            is_public=True,
            is_entry=True,
            line=1
        )

        role_types = {"AdminCap"}
        facts = generate_unused_arg_facts(func, role_types)
        # Only unused_value should be flagged
        expected = [Fact("UnusedArg", ("test::mixed", "unused_value", 2))]
        assert_facts_equal(facts, expected)


class TestStructShorthandUsage:
    """Tests for struct shorthand field syntax detection."""

    def test_struct_shorthand_counts_as_usage(self):
        """Struct shorthand `field` (equiv to `field: field`) counts as variable usage."""
        from move.cst_to_ir import build_ir_from_source
        from move.parse import parse_move_source

        source = '''
module 0x1::test {
    struct MyStruct has drop {
        value: u64,
        name: u64
    }

    public fun use_shorthand(value: u64, name: u64): MyStruct {
        MyStruct { value, name }
    }
}
'''
        root = parse_move_source(source)
        module = build_ir_from_source(source, root)
        assert module is not None

        func = module.functions[0]
        assert func.name == "test::use_shorthand"

        facts = generate_unused_arg_facts(func)
        # Both value and name are used via shorthand syntax
        assert facts == [], f"Expected no unused args, got: {facts}"

    def test_struct_explicit_still_works(self):
        """Explicit struct field syntax `field: var` still works."""
        from move.cst_to_ir import build_ir_from_source
        from move.parse import parse_move_source

        source = '''
module 0x1::test {
    struct MyStruct has drop {
        value: u64
    }

    public fun use_explicit(input: u64): MyStruct {
        MyStruct { value: input }
    }
}
'''
        root = parse_move_source(source)
        module = build_ir_from_source(source, root)
        assert module is not None

        func = module.functions[0]
        facts = generate_unused_arg_facts(func)
        # input is used in explicit field assignment
        assert facts == [], f"Expected no unused args, got: {facts}"

    def test_mixed_shorthand_and_explicit(self):
        """Mix of shorthand and explicit syntax works correctly."""
        from move.cst_to_ir import build_ir_from_source
        from move.parse import parse_move_source

        source = '''
module 0x1::test {
    struct MyStruct has drop {
        a: u64,
        b: u64,
        c: u64
    }

    public fun mixed(a: u64, b: u64, unused: u64): MyStruct {
        MyStruct { a, b: b, c: 42 }
    }
}
'''
        root = parse_move_source(source)
        module = build_ir_from_source(source, root)
        assert module is not None

        func = module.functions[0]
        facts = generate_unused_arg_facts(func)
        # Only 'unused' should be flagged
        expected = [Fact("UnusedArg", ("test::mixed", "unused", 2))]
        assert_facts_equal(facts, expected)


class TestExpressionListFalsePosivites:
    """Tests for expression_list false positive fixes from plan."""

    def test_parenthesized_multiplication_no_false_positive(self):
        """Parenthesized expression (a * b) / c should not flag a and b as unused."""
        from move.cst_to_ir import build_ir_from_source
        from move.parse import parse_move_source

        source = '''
module 0x1::utils {
    public fun mul_div(a: u64, b: u64, c: u64): u64 {
        (a * b) / c
    }
}
'''
        root = parse_move_source(source)
        module = build_ir_from_source(source, root)
        assert module is not None

        func = module.functions[0]
        assert func.name == "utils::mul_div"

        facts = generate_unused_arg_facts(func)
        # a, b, c are all used - should have no unused arg facts
        assert facts == [], f"Expected no unused args, got: {facts}"

    def test_tuple_return_no_false_positive(self):
        """Tuple return (field1, field2, field3) should not flag parameter as unused."""
        from move.cst_to_ir import build_ir_from_source
        from move.parse import parse_move_source

        source = '''
module 0x1::quiz {
    struct Quiz has drop {
        title: u64,
        description: u64,
        reward: u64
    }

    public fun get_quiz_info(quiz: Quiz): (u64, u64, u64) {
        (quiz.title, quiz.description, quiz.reward)
    }
}
'''
        root = parse_move_source(source)
        module = build_ir_from_source(source, root)
        assert module is not None

        func = module.functions[0]
        assert func.name == "quiz::get_quiz_info"

        facts = generate_unused_arg_facts(func)
        # quiz is used via field accesses in tuple - should have no unused arg facts
        assert facts == [], f"Expected no unused args, got: {facts}"

    def test_nested_parentheses_no_false_positive(self):
        """Nested parentheses should properly track all variables."""
        from move.cst_to_ir import build_ir_from_source
        from move.parse import parse_move_source

        source = '''
module 0x1::curve {
    public fun get_info(arg0: u64, arg1: u64, arg2: u64): u64 {
        ((arg0 + arg1) * arg2)
    }
}
'''
        root = parse_move_source(source)
        module = build_ir_from_source(source, root)
        assert module is not None

        func = module.functions[0]
        facts = generate_unused_arg_facts(func)
        # All args are used - should have no unused arg facts
        assert facts == [], f"Expected no unused args, got: {facts}"

from typing import List

from move.taint_facts import (
    is_transfer_sink,
    is_state_write_sink,
    is_sender_source,
    generate_stmt_facts,
    generate_taint_base_facts,
)
from move.extract import is_reference_type
from move.ir import (
    Function,
    Param,
    LetStmt,
    ExprStmt,
    IfStmt,
    Call,
    VarRef,
    FieldAccess,
    BinOp,
    Expr,
    expr_vars
)
from core.facts import Fact

def sorted_facts(facts: List[Fact]) -> List[Fact]:
    return sorted(facts, key=lambda f: (f.name, f.args))

def assert_facts_equal(actual: List[Fact], expected: List[Fact]):
    assert sorted_facts(actual) == sorted_facts(expected)

# Tests for Sink Detection Helpers

def test_is_transfer_sink():
    assert is_transfer_sink("transfer::transfer")
    assert is_transfer_sink("sui::transfer::public_transfer")
    assert is_transfer_sink("some::module::transfer")  # Suffix match
    assert not is_transfer_sink("coin::transfer_coin")
    assert not is_transfer_sink("my_transfer::something")

def test_is_state_write_sink():
    assert is_state_write_sink("balance::join")
    assert is_state_write_sink("my::coin::put")  # Suffix match
    assert not is_state_write_sink("some::module::add_field")

def test_is_sender_source():
    """Test sender source detection for both traditional and method-call syntax."""
    # Traditional call syntax (qualified)
    assert is_sender_source("tx_context::sender")
    assert is_sender_source("sui::tx_context::sender")
    assert is_sender_source("one::tx_context::sender")

    # Method-call syntax: ctx.sender() → callee is "sender" or "module::sender"
    assert is_sender_source("sender"), "Method-call syntax (unqualified) should be detected"
    assert is_sender_source("test::config_write::sender"), "Method-call syntax (qualified) should be detected"
    assert is_sender_source("any::module::sender"), "Any module with sender should match"

    # Should NOT match other senders
    assert not is_sender_source("get_sender"), "get_sender is not sender"
    assert not is_sender_source("some_other_sender"), "some_other_sender is not sender"
    assert not is_sender_source("sender_address"), "sender_address is not sender"

# Tests for collect_var_refs

def test_collect_var_refs_simple():
    assert expr_vars(VarRef(id="e1", name="x")) == ["x"]

def test_collect_var_refs_field_access():
    expr = FieldAccess(id="e2", base=VarRef(id="e1", name="obj"), field="f")
    assert expr_vars(expr) == ["obj"]

def test_collect_var_refs_binop():
    expr = BinOp(id="e3", op="+", left=VarRef(id="e1", name="a"), right=VarRef(id="e2", name="b"))
    assert sorted(expr_vars(expr)) == ["a", "b"]

def test_collect_var_refs_call():
    expr = Call(id="e4", callee="foo", args=[
        VarRef(id="e1", name="arg1"),
        FieldAccess(id="e3", base=VarRef(id="e2", name="obj"), field="f")
    ])
    assert sorted(expr_vars(expr)) == ["arg1", "obj"]

def test_collect_var_refs_none():
    assert expr_vars(Expr(id="e1")) == []

# Tests for generate_stmt_facts

def test_generate_stmt_facts_let_simple():
    stmt = LetStmt(id="s1", line=1, bindings=["x"], value=VarRef(id="e1", name="y"), type_ann=None)
    facts = generate_stmt_facts("my_func", stmt)
    expected = [Fact("Assigns", ("my_func", "s1", "x", ("y",)))]
    assert_facts_equal(facts, expected)

def test_generate_stmt_facts_let_call():
    call = Call(id="e1", callee="get_data", args=[VarRef(id="e2", name="arg_v")])
    stmt = LetStmt(id="s2", line=2, bindings=["res"], value=call, type_ann=None)
    facts = generate_stmt_facts("my_func", stmt)
    expected = [
        Fact("Assigns", ("my_func", "s2", "res", ("arg_v",))),
        Fact("CallResult", ("my_func", "s2", "res", "get_data")),
        Fact("CallArg", ("my_func", "s2", "get_data", 0, ("arg_v",))),
    ]
    assert_facts_equal(facts, expected)

def test_generate_stmt_facts_expr_stmt_transfer_sink():
    call = Call(id="e1", callee="sui::transfer::transfer", args=[
        VarRef(id="e2", name="obj"),
        VarRef(id="e3", name="recipient")
    ])
    stmt = ExprStmt(id="s3", line=3, expr=call)
    facts = generate_stmt_facts("my_func", stmt)
    expected = [
        # CallArg facts for interprocedural analysis
        Fact("CallArg", ("my_func", "s3", "sui::transfer::transfer", 0, ("obj",))),
        Fact("CallArg", ("my_func", "s3", "sui::transfer::transfer", 1, ("recipient",))),
        Fact("TransferSink", ("my_func", "s3", "sui::transfer::transfer")),
        Fact("SinkUsesVar", ("my_func", "s3", "recipient", "recipient")),
        # First arg (obj) is the value being transferred
        Fact("SinkUsesVar", ("my_func", "s3", "obj", "transfer_value")),
    ]
    assert_facts_equal(facts, expected)

def test_generate_stmt_facts_if_stmt():
    cond = VarRef(id="e_cond", name="c")
    then_stmt = ExprStmt(id="s_then", line=5, expr=Call(id="e_then", callee="then_call", args=[]))
    else_stmt = ExprStmt(id="s_else", line=7, expr=Call(id="e_else", callee="else_call", args=[]))
    stmt = IfStmt(id="s4", line=4, condition=cond, then_body=[then_stmt], else_body=[else_stmt])
    facts = generate_stmt_facts("my_func", stmt)
    # We don't check the recursive calls' output here, just the condition check
    assert Fact("ConditionCheck", ("my_func", "s4", ("c",))) in facts
    assert len(facts) == 1 # Only ConditionCheck is generated for these branches

# Tests for generate_taint_base_facts

def test_generate_taint_base_facts():
    param1 = Param(name="p_obj", typ="T", is_mut=False, idx=0)
    param2 = Param(name="p_addr", typ="address", is_mut=False, idx=1)

    let_stmt = LetStmt(id="s1", line=10, bindings=["x"], value=VarRef(id="e1", name="p_obj"), type_ann=None)

    func = Function(
        name="test_func",
        params=[param1, param2],
        ret_type=None,
        body=[let_stmt],
        is_public=True,
        is_entry=True,
        line=5,
    )

    facts = generate_taint_base_facts(func)

    expected = [
        Fact("TaintSource", ("test_func", "p_obj", 0)),
        Fact("TaintSource", ("test_func", "p_addr", 1)),
        Fact("Assigns", ("test_func", "s1", "x", ("p_obj",))),
    ]

    assert_facts_equal(facts, expected)


# Tests for is_reference_type

def test_is_reference_type_immutable_ref():
    assert is_reference_type("&Pool")
    assert is_reference_type("&SuiSystemState")
    assert is_reference_type("& Pool")  # with space

def test_is_reference_type_mutable_ref():
    assert is_reference_type("&mut Pool")
    assert is_reference_type("&mut NativePool")
    assert is_reference_type("&mut TxContext")

def test_is_reference_type_value_types():
    assert not is_reference_type("u64")
    assert not is_reference_type("u128")
    assert not is_reference_type("address")
    assert not is_reference_type("bool")
    assert not is_reference_type("Pool")  # owned object, not reference
    assert not is_reference_type("Coin<SUI>")
    assert not is_reference_type("vector<u8>")


# Tests for taint source generation with reference params

def test_generate_taint_base_facts_skips_ref_params():
    """Reference params should NOT be taint sources - they represent object access, not user-provided data."""
    param_ref = Param(name="pool", typ="&mut Pool", is_mut=True, idx=0)
    param_val = Param(name="amount", typ="u64", is_mut=False, idx=1)
    param_ctx = Param(name="ctx", typ="&mut TxContext", is_mut=True, idx=2)

    func = Function(
        name="test_func",
        params=[param_ref, param_val, param_ctx],
        ret_type=None,
        body=[],
        is_public=True,
        is_entry=True,
        line=1,
    )

    facts = generate_taint_base_facts(func)

    # Only amount (value param) should be a taint source
    taint_sources = [f for f in facts if f.name == "TaintSource"]
    assert len(taint_sources) == 1
    assert taint_sources[0].args == ("test_func", "amount", 1)


def test_generate_taint_base_facts_immutable_ref_skipped():
    """Immutable references (&T) should also be skipped as taint sources."""
    param_ref = Param(name="state", typ="&State", is_mut=False, idx=0)
    param_addr = Param(name="recipient", typ="address", is_mut=False, idx=1)

    func = Function(
        name="read_func",
        params=[param_ref, param_addr],
        ret_type=None,
        body=[],
        is_public=True,
        is_entry=False,
        line=1,
    )

    facts = generate_taint_base_facts(func)

    taint_sources = [f for f in facts if f.name == "TaintSource"]
    assert len(taint_sources) == 1
    assert taint_sources[0].args == ("read_func", "recipient", 1)


def test_generate_taint_base_facts_all_refs_no_taint():
    """Function with only reference params should have no taint sources."""
    param1 = Param(name="self", typ="&mut NativePool", is_mut=True, idx=0)
    param2 = Param(name="wrapper", typ="&mut SuiSystemState", is_mut=True, idx=1)
    param3 = Param(name="ctx", typ="&mut TxContext", is_mut=True, idx=2)

    func = Function(
        name="rebalance",
        params=[param1, param2, param3],
        ret_type=None,
        body=[],
        is_public=True,
        is_entry=True,
        line=1,
    )

    facts = generate_taint_base_facts(func)

    taint_sources = [f for f in facts if f.name == "TaintSource"]
    assert len(taint_sources) == 0


# Tests for GenericCallArg fact generation

def test_generic_call_arg_simple_type():
    """GenericCallArg is generated for simple type parameter T."""
    call = Call(id="e1", callee="coin::take", args=[], type_args=["T"])
    stmt = ExprStmt(id="s1", line=1, expr=call)
    facts = generate_stmt_facts("test_func", stmt)

    generic_facts = [f for f in facts if f.name == "GenericCallArg"]
    assert len(generic_facts) == 1
    assert generic_facts[0].args == ("test_func", "s1", "coin::take", 0, "T")


def test_generic_call_arg_multiple_types():
    """GenericCallArg is generated for each type parameter."""
    call = Call(id="e1", callee="some_func", args=[], type_args=["T0", "T1", "U"])
    stmt = ExprStmt(id="s1", line=1, expr=call)
    facts = generate_stmt_facts("test_func", stmt)

    generic_facts = [f for f in facts if f.name == "GenericCallArg"]
    assert len(generic_facts) == 3
    assert ("test_func", "s1", "some_func", 0, "T0") in [f.args for f in generic_facts]
    assert ("test_func", "s1", "some_func", 1, "T1") in [f.args for f in generic_facts]
    assert ("test_func", "s1", "some_func", 2, "U") in [f.args for f in generic_facts]


def test_generic_call_arg_in_let_stmt():
    """GenericCallArg is generated for calls in let statements."""
    call = Call(id="e1", callee="std::type_name::get", args=[], type_args=["T"])
    stmt = LetStmt(id="s1", line=1, bindings=["name"], value=call, type_ann=None)
    facts = generate_stmt_facts("test_func", stmt)

    generic_facts = [f for f in facts if f.name == "GenericCallArg"]
    assert len(generic_facts) == 1
    assert generic_facts[0].args == ("test_func", "s1", "std::type_name::get", 0, "T")


def test_generic_call_arg_no_type_args():
    """No GenericCallArg for calls without type arguments."""
    call = Call(id="e1", callee="foo", args=[VarRef(id="e2", name="x")], type_args=[])
    stmt = ExprStmt(id="s1", line=1, expr=call)
    facts = generate_stmt_facts("test_func", stmt)

    generic_facts = [f for f in facts if f.name == "GenericCallArg"]
    assert len(generic_facts) == 0


def test_generic_call_arg_nested_type_extracted():
    """GenericCallArg for nested types (e.g., Balance<T>) extracts inner T.

    This tests that when the IR contains extracted inner type params,
    the fact generation correctly creates GenericCallArg facts for them.
    """
    # IR already has extracted type params (done by cst_to_ir)
    call = Call(id="e1", callee="coin::from_balance", args=[], type_args=["T"])
    stmt = ExprStmt(id="s1", line=1, expr=call)
    facts = generate_stmt_facts("test_func", stmt)

    generic_facts = [f for f in facts if f.name == "GenericCallArg"]
    assert len(generic_facts) == 1
    assert generic_facts[0].args == ("test_func", "s1", "coin::from_balance", 0, "T")


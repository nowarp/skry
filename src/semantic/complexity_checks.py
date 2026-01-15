"""
Code complexity and quality property checks.

Contains checks for:
- version_check_inconsistent (THE BIG ONE - 185 lines)
- unused, duplicated_branch_condition, duplicated_branch_body
"""

from typing import List, Dict, Set, TYPE_CHECKING

from core.facts import Fact, names_match
from rules.ir import Rule, Condition
from rules.ir import Binding
from core.utils import get_simple_name

from semantic.helpers import (
    get_function_binding_key,
    gather_facts_for_func,
    has_fact,
    apply_negation,
)

if TYPE_CHECKING:
    from semantic.checker import SemanticChecker
    from core.context import ProjectContext


def _get_simple_call_graph(ctx: "ProjectContext") -> Dict[str, Set[str]]:
    """Get cached simple-name call graph (caller -> {simple_name callees})."""
    if hasattr(ctx, "_simple_call_graph"):
        return ctx._simple_call_graph  # type: ignore[return-value]

    call_graph: Dict[str, Set[str]] = {}
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "InFun":
                caller = fact.args[0]
                call_id = fact.args[1]
                callee_name = call_id.rsplit("@", 1)[0] if "@" in call_id else call_id
                callee_simple = get_simple_name(callee_name)
                if caller not in call_graph:
                    call_graph[caller] = set()
                call_graph[caller].add(callee_simple)

    ctx._simple_call_graph = call_graph  # type: ignore[attr-defined]
    return call_graph


def _get_inline_version_check_funcs(ctx: "ProjectContext") -> Set[str]:
    """Get cached set of functions with inline version checks."""
    if hasattr(ctx, "_inline_version_check_funcs"):
        return ctx._inline_version_check_funcs  # type: ignore[return-value]

    funcs: Set[str] = set()
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "ConditionFieldAccess" and len(fact.args) >= 4 and fact.args[3] == "version":
                func_with_inline_check = fact.args[0]
                funcs.add(get_simple_name(func_with_inline_check))

    ctx._inline_version_check_funcs = funcs  # type: ignore[attr-defined]
    return funcs


def check_version_check_inconsistent(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if function is missing version check while other functions in same module have it."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    # 1. Check if project has versioning
    has_versioning = False
    version_check_funcs: Set[str] = set()
    version_check_methods: Set[str] = set()
    for fact in checker.ctx.project_facts:
        if fact.name == "FeatureVersion" and len(fact.args) > 0 and fact.args[0] is True:
            has_versioning = True
        if fact.name == "HasVersionCheck":
            version_check_funcs.add(fact.args[0])
        if fact.name == "IsVersionCheckMethod":
            version_check_methods.add(fact.args[0])

    if not has_versioning:
        return apply_negation(False, condition.negation)

    # Common version check method patterns
    common_version_methods = {
        "verify_version",
        "verify_authority",
        "verify_witness",
        "version_check",
        "assert_version",
        "check_version",
    }
    version_check_methods.update(common_version_methods)

    if not version_check_funcs and not version_check_methods:
        return apply_negation(False, condition.negation)

    # Use cached call graph and inline version check functions
    call_graph = _get_simple_call_graph(checker.ctx)
    version_check_methods.update(_get_inline_version_check_funcs(checker.ctx))

    def is_version_check_callee(callee_simple: str) -> bool:
        for vc_func in version_check_funcs:
            if get_simple_name(vc_func) == callee_simple:
                return True
        return callee_simple in version_check_methods

    version_check_cache: Dict[str, bool] = {}

    def calls_version_check(target_func: str, visited: Set[str] | None = None) -> bool:
        if visited is None:
            visited = set()

        if target_func in version_check_cache:
            return version_check_cache[target_func]

        if target_func in visited:
            return False
        visited.add(target_func)

        callees = call_graph.get(target_func, set())

        for callee in callees:
            if is_version_check_callee(callee):
                version_check_cache[target_func] = True
                return True

        for callee_simple in callees:
            for full_func in call_graph.keys():
                if get_simple_name(full_func) == callee_simple and full_func not in visited:
                    if calls_version_check(full_func, visited):
                        version_check_cache[target_func] = True
                        return True

        version_check_cache[target_func] = False
        return False

    # 2. Collect all facts for checking
    all_facts = gather_facts_for_func(checker, facts, func_name) + list(checker.ctx.project_facts)

    # 3. Check if this function calls any version check function
    if calls_version_check(func_name):
        return apply_negation(False, condition.negation)

    # Check for inline version checks via ConditionFieldAccess on "version" field
    has_inline_version_check = has_fact(
        all_facts,
        "ConditionFieldAccess",
        lambda f: len(f.args) >= 4 and names_match(f.args[0], func_name) and f.args[3] == "version",
    )

    if has_inline_version_check:
        return apply_negation(False, condition.negation)

    # 4. Find same-module functions
    same_module_funcs = set()
    for fact in all_facts:
        if fact.name == "SameModule":
            if names_match(fact.args[0], func_name):
                same_module_funcs.add(fact.args[1])
            elif names_match(fact.args[1], func_name):
                same_module_funcs.add(fact.args[0])

    if not same_module_funcs:
        return apply_negation(False, condition.negation)

    # 5. Check if any same-module function CALLS a version check function OR has inline check
    for other_func in same_module_funcs:
        if calls_version_check(other_func):
            return apply_negation(True, condition.negation)

        # Check for inline version check in other_func
        if has_fact(
            all_facts,
            "ConditionFieldAccess",
            lambda f: len(f.args) >= 4 and names_match(f.args[0], other_func) and f.args[3] == "version",
        ):
            return apply_negation(True, condition.negation)

    return apply_negation(False, condition.negation)


def check_unused(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if a function argument is unused."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)
    found = has_fact(all_facts, "UnusedArg", lambda f: f.args[0] == func_name)
    return apply_negation(found, condition.negation)


def check_duplicated_branch_condition(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if function has duplicated branch conditions (RCO-1)."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    found = has_fact(facts, "DuplicatedBranchCondition", lambda f: names_match(f.args[0], func_name))
    return apply_negation(found, condition.negation)


def check_duplicated_branch_body(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if function has duplicated branch bodies (code smell)."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    found = has_fact(facts, "DuplicatedBranchBody", lambda f: names_match(f.args[0], func_name))
    return apply_negation(found, condition.negation)

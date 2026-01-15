"""
Guard tracking for taint sinks.

GuardedSink facts track which sinks are protected by authorization checks.
This enables per-sink guard analysis instead of per-function propagation.

Guard types:
- "sender" - HasSenderEqualityCheck fact (sender equality check for authorization)
- "role:TypeName" - ChecksCapability fact (capability/role parameter)
- "version" - HasVersionCheck fact
- "pause" - ChecksPause fact
- "lock" - ChecksLock fact
"""

from typing import Dict, List, Set

from core.context import ProjectContext
from core.facts import Fact
from core.utils import debug


def collect_function_guards(ctx: ProjectContext) -> Dict[str, Set[str]]:
    """
    Collect guards for each function from file facts.

    Returns: func_name -> set of guard types ("sender", "role:AdminCap", etc.)
    """
    func_guards: Dict[str, Set[str]] = {}

    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "HasSenderEqualityCheck":
                func_name = fact.args[0]
                if func_name not in func_guards:
                    func_guards[func_name] = set()
                func_guards[func_name].add("sender")
            elif fact.name == "ChecksCapability":
                role_type, func_name = fact.args
                if func_name not in func_guards:
                    func_guards[func_name] = set()
                func_guards[func_name].add(f"role:{role_type}")
            elif fact.name == "HasVersionCheck":
                func_name = fact.args[0]
                if func_name not in func_guards:
                    func_guards[func_name] = set()
                func_guards[func_name].add("version")
            elif fact.name == "ChecksPause":
                func_name = fact.args[0]
                if func_name not in func_guards:
                    func_guards[func_name] = set()
                func_guards[func_name].add("pause")
            elif fact.name == "ChecksLock":
                func_name = fact.args[0]
                if func_name not in func_guards:
                    func_guards[func_name] = set()
                func_guards[func_name].add("lock")

    # Also collect from project_facts (backup for pause/lock if stored there)
    for fact in ctx.project_facts:
        if fact.name == "ChecksPause":
            func_name = fact.args[0]
            if func_name not in func_guards:
                func_guards[func_name] = set()
            func_guards[func_name].add("pause")
        elif fact.name == "ChecksLock":
            func_name = fact.args[0]
            if func_name not in func_guards:
                func_guards[func_name] = set()
            func_guards[func_name].add("lock")

    return func_guards


def make_guarded_sink_facts(func_name: str, stmt_id: str, guards: Set[str]) -> List[Fact]:
    """Create GuardedSink facts for each guard type."""
    return [Fact("GuardedSink", (func_name, stmt_id, guard)) for guard in guards]


def enrich_summaries_with_guards(ctx: ProjectContext) -> None:
    """
    Enrich function summaries with guard information from file facts.
    Must run after summaries are computed and guard facts exist.
    """
    func_guards = collect_function_guards(ctx)

    for func_name, summary in ctx.function_summaries.items():
        if func_name in func_guards:
            summary.guards = func_guards[func_name]


def generate_guarded_sink_facts(ctx: ProjectContext) -> int:
    """
    Generate GuardedSink facts by joining sink facts with guard facts.

    For each sink fact (TaintedTransferRecipient, etc.), if the function
    has guards (HasSenderEqualityCheck, ChecksCapability, etc.), emit GuardedSink.

    Guards come from two sources:
    1. Direct file-level facts (HasSenderEqualityCheck, ChecksCapability, etc.)
    2. Function summaries (which have transitively propagated guards from callees)

    Returns: number of GuardedSink facts generated.
    """
    # Collect guards from file facts
    func_guards = collect_function_guards(ctx)

    # Merge in guards from function summaries (transitively propagated)
    if hasattr(ctx, "function_summaries") and ctx.function_summaries:
        for func_name, summary in ctx.function_summaries.items():
            if summary.guards:
                if func_name not in func_guards:
                    func_guards[func_name] = set()
                func_guards[func_name].update(summary.guards)

    if not func_guards:
        return 0

    # Check for TaintedAtSink facts
    count = 0
    for file_path, file_ctx in ctx.source_files.items():
        new_facts = []
        for fact in file_ctx.facts:
            if fact.name != "TaintedAtSink":
                continue

            # TaintedAtSink(func_name, source, stmt_id, sink_type, cap)
            func_name = fact.args[0]
            stmt_id = fact.args[2]

            # Check if function has guards
            guards = func_guards.get(func_name, set())
            for guard_type in guards:
                guarded_fact = Fact("GuardedSink", (func_name, stmt_id, guard_type))
                if guarded_fact not in file_ctx.facts and guarded_fact not in new_facts:
                    new_facts.append(guarded_fact)
                    count += 1

        file_ctx.facts.extend(new_facts)

    if count > 0:
        debug(f"Generated {count} GuardedSink facts")

    return count

"""Single-step ownership transfer detection."""

from typing import Optional, Set

from core.context import ProjectContext
from core.facts import Fact
from core.utils import debug


def generate_ownership_transfer_facts(ctx: ProjectContext) -> None:
    """
    Generate ownership transfer pattern facts.

    1. Find functions taking privileged cap by-value + calling transfer
    2. Check if recipient is tainted (TaintedTransferRecipient exists)
    3. Check if module has two-step pattern (pending field + offer/claim)
    4. Generate SingleStepOwnershipTransfer for violations
    """
    # Collect all privileged types (IsCapability or IsPrivileged)
    privileged_types = _collect_privileged_types(ctx)
    if not privileged_types:
        debug("[ownership_transfer] No privileged types found")
        return

    debug(f"[ownership_transfer] Found {len(privileged_types)} privileged types: {privileged_types}")

    # Collect module two-step patterns
    module_two_step = {}
    for file_ctx in ctx.source_files.values():
        module_path = file_ctx.module_path
        has_two_step = _module_has_two_step_pattern(file_ctx)
        module_two_step[module_path] = has_two_step
        if has_two_step:
            debug(f"[ownership_transfer] Module {module_path} has two-step pattern")
            file_ctx.facts.append(Fact("HasTwoStepOwnership", (module_path,)))

    count = 0
    # Check all functions across all files
    for file_ctx in ctx.source_files.values():
        module_path = file_ctx.module_path
        has_two_step = module_two_step.get(module_path, False)

        # Get all functions in this file
        functions = {f.args[0] for f in file_ctx.facts if f.name == "Fun"}

        for func_name in functions:
            # Check: takes privileged by value (check across all files for cross-module caps)
            cap_type = _takes_privileged_by_value(func_name, ctx, privileged_types)
            if not cap_type:
                continue

            # Check: has tainted recipient (transitively via IPA)
            if not _has_tainted_recipient(func_name, ctx):
                continue

            # Generate TakesPrivilegedByValue
            file_ctx.facts.append(Fact("TakesPrivilegedByValue", (func_name, cap_type)))

            # Propagate to global index
            if ctx.global_facts_index and func_name in ctx.global_facts_index:
                for facts_list in ctx.global_facts_index[func_name].values():
                    if not any(
                        f.name == "TakesPrivilegedByValue" and f.args[0] == func_name and f.args[1] == cap_type
                        for f in facts_list
                    ):
                        facts_list.append(Fact("TakesPrivilegedByValue", (func_name, cap_type)))

            # Check if cap's module has two-step pattern (cross-module aware)
            cap_module = cap_type.rsplit("::", 1)[0] if "::" in cap_type else module_path
            cap_has_two_step = module_two_step.get(cap_module, False)

            # Generate SingleStepOwnershipTransfer if no two-step pattern
            if not has_two_step and not cap_has_two_step:
                file_ctx.facts.append(Fact("SingleStepOwnershipTransfer", (func_name, cap_type)))
                count += 1

                # Propagate to global index
                if ctx.global_facts_index and func_name in ctx.global_facts_index:
                    for facts_list in ctx.global_facts_index[func_name].values():
                        if not any(
                            f.name == "SingleStepOwnershipTransfer" and f.args[0] == func_name and f.args[1] == cap_type
                            for f in facts_list
                        ):
                            facts_list.append(Fact("SingleStepOwnershipTransfer", (func_name, cap_type)))

                debug(f"[ownership_transfer] {func_name} performs single-step transfer of {cap_type}")

    if count > 0:
        debug(f"Generated {count} SingleStepOwnershipTransfer facts")


def _collect_privileged_types(ctx: ProjectContext) -> Set[str]:
    """Collect all privileged types (IsCapability or IsPrivileged), excluding NotPrivileged."""
    privileged_types = set()
    not_privileged = set()

    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name in ("IsCapability", "IsPrivileged"):
                privileged_types.add(fact.args[0])
            elif fact.name == "NotPrivileged":
                not_privileged.add(fact.args[0])

    # NotPrivileged overrides structural detection
    return privileged_types - not_privileged


def _takes_privileged_by_value(func_name: str, ctx: ProjectContext, privileged_types: Set[str]) -> Optional[str]:
    """Check if function takes privileged cap by value (not reference).

    Cross-module aware: checks FormalArg facts from all files via global_facts_index.
    """
    # Check all facts for this function (cross-file)
    all_facts = []
    for file_ctx in ctx.source_files.values():
        all_facts.extend(file_ctx.facts)

    if ctx.global_facts_index and func_name in ctx.global_facts_index:
        for facts_list in ctx.global_facts_index[func_name].values():
            all_facts.extend(facts_list)

    for fact in all_facts:
        if fact.name != "FormalArg" or fact.args[0] != func_name:
            continue
        param_type = fact.args[3]
        if param_type.startswith("&"):  # reference = not ownership transfer
            continue
        # Strip generics and resolve to FQN
        base_type = param_type.split("<")[0]
        func_module = func_name.rsplit("::", 1)[0] if "::" in func_name else ""

        # Resolve simple name to FQN using function's module context
        if "::" in base_type:
            resolved_type = base_type  # Already FQN
        else:
            resolved_type = f"{func_module}::{base_type}" if func_module else base_type

        # Check exact FQN match against privileged types (no names_match!)
        if resolved_type in privileged_types:
            return resolved_type
    return None


def _module_has_two_step_pattern(file_ctx) -> bool:
    """Check for pending field + separate write/read functions."""
    pending_fields = set()
    writes_pending = set()
    reads_pending = set()

    for fact in file_ctx.facts:
        if fact.name == "StructField":
            field_name = fact.args[2].lower()
            if "pending" in field_name:
                pending_fields.add((fact.args[0], fact.args[2]))
        elif fact.name == "WritesField":
            field_name = fact.args[2].lower()
            if "pending" in field_name:
                writes_pending.add(fact.args[0])  # func that writes
        elif fact.name == "ReadsField":
            field_name = fact.args[2].lower()
            if "pending" in field_name:
                reads_pending.add(fact.args[0])  # func that reads

    # Two-step = has pending field + different funcs write and read
    return bool(pending_fields) and bool(writes_pending) and bool(reads_pending)


def _has_tainted_recipient(func_name: str, ctx: ProjectContext) -> bool:
    """Check if function has tainted recipient (direct or via IPA call chain)."""
    # Collect all facts
    all_facts = []
    for file_ctx in ctx.source_files.values():
        all_facts.extend(file_ctx.facts)

    if ctx.global_facts_index and func_name in ctx.global_facts_index:
        for facts_list in ctx.global_facts_index[func_name].values():
            all_facts.extend(facts_list)

    # Get transitive callees for IPA
    funcs_to_check = {func_name}
    if ctx.call_graph and func_name in ctx.call_graph.transitive_callees:
        funcs_to_check.update(ctx.call_graph.transitive_callees[func_name])

    # Check if any function in call chain has tainted recipient (TaintedAtSink with sink_type='transfer_recipient')
    return any(
        f.name == "TaintedAtSink"
        and f.args[0] in funcs_to_check
        and len(f.args) > 3
        and f.args[3] == "transfer_recipient"
        for f in all_facts
    )

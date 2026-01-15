"""
Pause and lock check facts (direct only, no propagation).

Two separate mechanisms:
1. Lock: Per-object locks from IsLockField (unified classification)
   - IsLockField + ReadsField → ChecksLock → HasLockInfrastructure
2. Global Pause: From IsGlobalPauseField (PauseDetector)
   - IsGlobalPauseField → ChecksPause (direct only)

Per-sink guards are tracked via GuardedSink facts instead of propagation.
"""

from typing import Set, Optional

from core.context import ProjectContext
from core.facts import Fact
from core.utils import debug
from analysis.field_checks import derive_field_check_facts, find_functions_checking_field


def compute_pause_facts(ctx: ProjectContext) -> None:
    """
    Compute pause and lock related derived facts (direct only).

    1. Lock infrastructure: IsLockField + ReadsField → ChecksLock
    2. Global pause: IsGlobalPauseField → ChecksPause
    """
    # Part 1: Lock infrastructure (from unified field classification)
    derive_field_check_facts(
        ctx,
        field_category="lock",
        checks_fact_name="ChecksLock",
        infrastructure_fact_name="HasLockInfrastructure",
        debug_prefix="lock",
    )

    # Part 2: Global pause (from PauseDetector)
    _compute_global_pause_facts(ctx)


def _compute_global_pause_facts(ctx: ProjectContext) -> None:
    """
    Compute global pause facts using IsGlobalPauseField from PauseDetector.

    Uses find_functions_checking_field() to accurately match the specific
    struct.field combination, preventing collisions with other structs
    that have fields with the same name.

    Direct only - no call graph propagation. Guards tracked via GuardedSink.
    """
    # Step 1: Find THE pause config from PauseDetector
    pause_struct: Optional[str] = None
    pause_field: Optional[str] = None

    for fact in ctx.project_facts:
        if fact.name == "IsGlobalPauseField" and len(fact.args) >= 2:
            pause_struct = fact.args[0]
            pause_field = fact.args[1]
            break

    if not pause_struct or not pause_field:
        debug("[pause] No IsGlobalPauseField found, skipping")
        return

    debug(f"[pause] Found IsGlobalPauseField({pause_struct}, {pause_field})")

    # Step 2: Find functions that already have ChecksPause from PauseDetector
    initial_checks: Set[str] = set()
    for fact in ctx.project_facts:
        if fact.name == "ChecksPause":
            initial_checks.add(fact.args[0])

    debug(f"[pause] Initial ChecksPause from detector: {initial_checks}")

    # Step 3: Find functions that check this specific struct.field
    structural_checks = find_functions_checking_field(
        ctx,
        struct_type=pause_struct,
        field_name=pause_field,
        debug_prefix="pause",
    )

    # Combine initial (from LLM) and structural (from analysis)
    direct_checks = initial_checks | structural_checks

    debug(f"[pause] Combined direct checks: {len(direct_checks)}")

    # Step 4: Add direct ChecksPause facts (no propagation)
    # Add to both source_file.facts AND global_facts_index for transitive lookup
    count = 0
    for source_file in ctx.source_files.values():
        file_path = source_file.path
        for func_name in direct_checks:
            if any(f.name == "Fun" and f.args[0] == func_name for f in source_file.facts):
                fact = Fact("ChecksPause", (func_name,))
                if fact not in source_file.facts:
                    source_file.facts.append(fact)
                    # Also add to global_facts_index for transitive lookups
                    if func_name in ctx.global_facts_index:
                        if file_path in ctx.global_facts_index[func_name]:
                            if fact not in ctx.global_facts_index[func_name][file_path]:
                                ctx.global_facts_index[func_name][file_path].append(fact)
                    count += 1

    if count > 0:
        debug(f"[pause] Generated {count} ChecksPause facts (direct only)")

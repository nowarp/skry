"""
Pipeline passes for filter/classify rule evaluation.

Pass 3: Filter evaluation - structural checks, produces candidates
Pass 5: LLM facts generation - evaluates :classify clauses, generates LLM semantic facts
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple

from rules.ir import Binding
from rules.hy_loader import HyRule
from rules.utils import find_hy_bindings
from rules.eval_context import EvalContext
from core.context import ProjectContext
from core.utils import debug


@dataclass
class Candidate:
    """A candidate from filter evaluation, pending classify."""

    rule: HyRule
    file_path: str
    binding: Binding
    entity_name: str


@dataclass
class FilterResult:
    """Result of filter pass for all rules."""

    # Violations from filter-only rules (no :classify)
    violations: List[Tuple[HyRule, Binding]] = field(default_factory=list)

    # Candidates for classify pass (rules with :classify)
    candidates: List[Candidate] = field(default_factory=list)


def run_filter_pass(
    ctx: ProjectContext,
    rules: List[HyRule],
) -> FilterResult:
    """
    Pass 3: Filter evaluation.

    For each rule:
    - Evaluate :filter for all matching entities
    - If rule has no :classify: filter pass → violation (done)
    - If rule has :classify: filter pass → store candidate

    Returns:
        FilterResult with violations and candidates
    """
    result = FilterResult()

    for source_file in ctx.source_files:
        file_ctx = ctx.source_files[source_file]

        if file_ctx.is_test_only:
            continue

        facts = file_ctx.facts

        # Create EvalContext for this file
        eval_ctx = EvalContext(
            ctx=ctx,
            current_file=source_file,
            current_source=file_ctx.source_code,
            current_root=file_ctx.root,
        )

        for rule in rules:
            bindings = find_hy_bindings(rule, facts)

            if not bindings:
                continue

            reported_entities: Set[str] = set()

            for binding in bindings:
                entity_name = binding.get(rule.match_binding)

                if entity_name and entity_name in reported_entities:
                    continue

                try:
                    # Evaluate filter clause
                    if rule.filter_clause and not rule.filter_clause(entity_name, facts, eval_ctx):
                        debug(f"  [filter] {rule.name}: {entity_name} -> filtered out")
                        continue

                    debug(f"  [filter] {rule.name}: {entity_name} -> passed filter")

                    if rule.classify_clause:
                        # Has classify: store as candidate
                        if entity_name is None:
                            continue
                        candidate = Candidate(
                            rule=rule,
                            file_path=source_file,
                            binding=binding,
                            entity_name=entity_name,
                        )
                        result.candidates.append(candidate)
                    else:
                        # Filter-only rule: this is a violation
                        result.violations.append((rule, binding))
                        if entity_name:
                            reported_entities.add(entity_name)

                except Exception as e:
                    debug(f"  [filter] {rule.name}: {entity_name} -> error: {e}")

    debug(f"Pass 3: {len(result.violations)} filter-only violations, {len(result.candidates)} candidates for classify")
    return result


def run_llm_facts_pass(
    ctx: ProjectContext,
    filter_result: FilterResult,
) -> List[Tuple[HyRule, Binding]]:
    """
    Pass 5: LLM semantic facts generation.

    For each candidate from filter pass:
    - Evaluate :classify clause (triggers LLM fact generation)
    - LLM facts added to file_ctx.facts (positive OR negative)
    - If :classify returns True (negative fact): add to violations

    LLM Facts Generated:
    - LLMHasAccessControl / LLMVulnerableAccessControl
    - LLMHasSlippageProtection / LLMMissingSlippage
    - LLMHasUnlockOnAllPaths / LLMMissingUnlock
    - LLMCallerOwnsValue / LLMArbitraryDrain
    - LLMValueReachesRecipient / LLMMissingTransfer
    - LLMHasSetterAuth / LLMSensitiveSetter

    Returns:
        List of (rule, binding) violations (candidates with negative LLM facts)
    """
    violations: List[Tuple[HyRule, Binding]] = []

    # Group candidates by file for efficient eval context creation
    candidates_by_file: Dict[str, List[Candidate]] = {}
    for candidate in filter_result.candidates:
        if candidate.file_path not in candidates_by_file:
            candidates_by_file[candidate.file_path] = []
        candidates_by_file[candidate.file_path].append(candidate)

    # Track reported entities per rule to avoid duplicates
    reported: Dict[str, Set[str]] = {}

    for file_path, candidates in candidates_by_file.items():
        file_ctx = ctx.source_files[file_path]
        facts = file_ctx.facts

        eval_ctx = EvalContext(
            ctx=ctx,
            current_file=file_path,
            current_source=file_ctx.source_code,
            current_root=file_ctx.root,
        )

        for candidate in candidates:
            rule = candidate.rule
            entity_name = candidate.entity_name

            # Skip if already reported for this rule
            if rule.name not in reported:
                reported[rule.name] = set()
            if entity_name in reported[rule.name]:
                continue

            try:
                # Evaluate :classify clause - this generates LLM facts
                # Returns True if vulnerable (negative fact added)
                if rule.classify_clause is None:
                    continue
                if rule.classify_clause(entity_name, facts, eval_ctx):
                    debug(f"  [llm_facts] {rule.name}: {entity_name} -> VULNERABLE")
                    violations.append((rule, candidate.binding))
                    reported[rule.name].add(entity_name)
                else:
                    debug(f"  [llm_facts] {rule.name}: {entity_name} -> safe")

            except Exception as e:
                debug(f"  [llm_facts] {rule.name}: {entity_name} -> error: {e}")

    debug(f"Pass 5: {len(violations)} LLM violations")
    return violations

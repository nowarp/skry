"""
Analysis passes for building and propagating code facts.

Pass 1: Structural analysis - AST to facts
Pass 3: Fact propagation - derived facts, cross-file joins
"""

from analysis.structural import StructuralBuilder
from core.context import ProjectContext
from taint import run_structural_taint_analysis
from taint.generics import generate_generic_type_facts
from analysis.patterns import generate_sender_derived_param_facts
from analysis.field_tracking import generate_writes_field_facts, propagate_writes_field_to_callers
from analysis.access_control import generate_stdlib_capability_transfer_facts


def run_structural_analysis(ctx: ProjectContext, skip_tests: bool = False) -> None:
    """
    Extracts facts directly from AST and propagates them using cross-module
    interprocedural taint analysis.

    Args:
        skip_tests: If True, skip files in test/example directories.
    """
    from analysis.transfers import generate_value_extraction_facts
    from analysis.orphans import detect_orphan_txcontext_functions

    StructuralBuilder(skip_tests=skip_tests).build(ctx)
    run_structural_taint_analysis(ctx)  # Populates ctx.module_index with IR
    generate_stdlib_capability_transfer_facts(ctx)  # Needs CallResult facts from taint
    detect_orphan_txcontext_functions(ctx)  # Needs CallArg facts from taint analysis
    generate_writes_field_facts(ctx)  # Needs ctx.module_index from taint analysis
    propagate_writes_field_to_callers(ctx)  # IPA: propagate WritesField to callers
    generate_generic_type_facts(ctx)  # Needs GenericCallArg facts from taint
    generate_value_extraction_facts(ctx)
    generate_sender_derived_param_facts(ctx)  # Needs TrackedDerived from taint, must run before Pass 2


def run_fact_propagation(ctx: ProjectContext) -> None:
    """
    Must run after:
    - Pass 1: structural facts (FormalArg, IsSharedObject, SenderDerivedParam, etc.)
    - Pass 2: semantic facts (IsPrivileged, IsLockField, etc.)
    """
    from analysis.access_control import (
        generate_checks_role_facts,
        generate_init_impl_facts,
        generate_destroys_capability_facts,
        generate_capability_hierarchy_facts,
    )
    from analysis.derived_facts import (
        compute_derived_facts,
        recompute_transfers_from_sender,
        generate_has_privileged_setter_facts,
        generate_writes_protocol_invariant_facts,
    )
    from analysis.user_assets import detect_user_asset_containers
    from analysis.pause import compute_pause_facts
    from analysis.ownership_transfer import generate_ownership_transfer_facts
    from analysis.patterns import generate_creates_capability_facts, propagate_creates_capability_facts
    from taint.cross_module import propagate_taint_across_modules
    from taint import enrich_summaries_with_guards, generate_guarded_sink_facts
    from analysis.cap_ir import (
        compute_address_sources,
        derive_cap_ownership,
        detect_capability_takeover,
        detect_phantom_type_mismatch,
        detect_capability_leak_via_store,
    )

    # Regenerate CreatesCapability after LLM IsCapability facts are available
    generate_creates_capability_facts(ctx)
    propagate_creates_capability_facts(ctx)

    # Generate InitImpl facts (needs Transfers, SharesObject, CreatesCapability)
    generate_init_impl_facts(ctx)

    # Regenerate ChecksCapability after LLM IsCapability facts are available (fixes cache inconsistency)
    generate_checks_role_facts(ctx)
    generate_capability_hierarchy_facts(ctx)  # Regenerate after LLM IsCapability facts
    generate_destroys_capability_facts(ctx)  # Needs IsCapability facts
    compute_derived_facts(ctx)  # Compute guards, shared object ops, etc.
    detect_user_asset_containers(ctx)
    compute_pause_facts(ctx)
    generate_has_privileged_setter_facts(ctx)  # Detect privileged setters for mutable config fields
    generate_writes_protocol_invariant_facts(ctx)  # Detect writes to protocol invariant fields
    generate_ownership_transfer_facts(ctx)  # Detect single-step ownership transfers
    enrich_summaries_with_guards(ctx)  # Add guards to summaries after all guard facts exist
    propagate_taint_across_modules(ctx)
    recompute_transfers_from_sender(ctx)  # Needs TrackedDerived from cross-module taint propagation
    generate_guarded_sink_facts(ctx)  # Join sinks with guards

    # cap_ir foundation: address class tracking and capability ownership
    compute_address_sources(ctx)  # Classify address value origins
    derive_cap_ownership(ctx)  # Determine capability ownership from init patterns
    detect_capability_takeover(ctx)  # Detect capability takeover vulnerabilities
    detect_phantom_type_mismatch(ctx)  # Detect phantom type mismatches in cap guards
    detect_capability_leak_via_store(ctx)  # Detect caps stored in shared objects


__all__ = ["StructuralBuilder", "run_structural_analysis", "run_fact_propagation"]

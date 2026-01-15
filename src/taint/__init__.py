"""Taint analysis module."""

from taint.interproc import run_structural_taint_analysis
from taint.guards import (
    generate_guarded_sink_facts,
    enrich_summaries_with_guards,
)

__all__ = ["run_structural_taint_analysis", "generate_guarded_sink_facts", "enrich_summaries_with_guards"]

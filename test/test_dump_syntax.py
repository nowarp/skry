"""Tests for dump_syntax to ensure it stays up-to-date."""

from rules.ir import PropName


# These must match the categories in main.py dump_syntax()
DUMP_SYNTAX_CATEGORIES = {
    "Access Control": ["public", "entry", "transfer", "checks_capability", "checks_sender", "is_init"],
    "Taint Analysis": lambda structural: [p for p in structural if p.startswith("tainted_") or "sanitized" in p],
    "Oracle": lambda structural: [p for p in structural if "oracle" in p or "price" in p],
    "CFG Patterns": ["missing_transfer", "double_init", "missing_price_update", "missing_slippage"],
    "Other": ["exists", "typed", "returns_mutable_ref", "transfers_to_zero_address", "weak_randomness", "orphan_txcontext", "orphan_capability", "orphan_event", "duplicated_branch_condition", "duplicated_branch_body", "self_recursive", "sensitive_event_leak", "unused", "version_check_inconsistent"],
}


def test_all_structural_properties_are_categorized():
    """Ensure dump_syntax categories cover all STRUCTURAL_PROPERTIES.

    If this test fails, update BOTH:
    1. DUMP_SYNTAX_CATEGORIES in this file
    2. The categories dict in main.py dump_syntax()
    """
    structural = PropName.STRUCTURAL_PROPERTIES

    categorized = set()
    for cat_name, props in DUMP_SYNTAX_CATEGORIES.items():
        if callable(props):
            # Dynamic category (e.g., all tainted_* properties)
            cat_props = props(structural)
        else:
            cat_props = props
        categorized.update(p for p in cat_props if p in structural)

    missing = structural - categorized
    extra = categorized - structural

    assert not missing, (
        f"Properties in STRUCTURAL_PROPERTIES but not in dump_syntax categories: {missing}\n"
        f"Add them to the appropriate category in main.py dump_syntax() and test_dump_syntax.py"
    )
    assert not extra, (
        f"Properties in dump_syntax categories but not in STRUCTURAL_PROPERTIES: {extra}\n"
        f"Remove them from main.py dump_syntax() and test_dump_syntax.py"
    )


def test_structural_properties_exist():
    """Ensure STRUCTURAL_PROPERTIES is not empty (sanity check)."""
    assert len(PropName.STRUCTURAL_PROPERTIES) > 0, "STRUCTURAL_PROPERTIES should not be empty"

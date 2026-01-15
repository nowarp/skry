from typing import List

from core.facts import Fact, get_caps, get_events
from rules.ir import Binding
from .hy_loader import HyRule


def collect_required_features(rules: List[HyRule]) -> set:
    """
    Collect required features from all rules.

    Features are auto-detected from filter/classify clauses at macro expansion time.
    Returns: Set of feature names (e.g., {"version", "category"})
    """
    features = set()
    for rule in rules:
        if isinstance(rule, HyRule) and hasattr(rule, "features"):
            features.update(rule.features)
    return features


def find_hy_bindings(rule: HyRule, facts: List[Fact]) -> List[Binding]:
    """
    Find bindings for a Hy rule based on its match pattern.

    Hy rules use simpler matching:
    - match_pattern: "fun", "capability", "event", "const"
    - match_modifiers: ["public", "entry"]
    - match_binding: variable name (e.g., "f")
    """
    bindings = []
    pattern = rule.match_pattern
    modifiers = rule.match_modifiers
    binding_name = rule.match_binding

    if pattern == "fun":
        for fact in facts:
            if fact.name != "Fun":
                continue
            func_name = fact.args[0]

            if "public" in modifiers:
                if not any(f.name == "IsPublic" and f.args[0] == func_name for f in facts):
                    continue
            if "entry" in modifiers:
                if not any(f.name == "IsEntry" and f.args[0] == func_name for f in facts):
                    continue

            bindings.append(Binding({binding_name: func_name}))

    elif pattern == "capability":
        caps = get_caps(facts)
        for cap_name in caps:
            bindings.append(Binding({binding_name: cap_name}))

    elif pattern == "event":
        events = get_events(facts)
        for event_name in events:
            bindings.append(Binding({binding_name: event_name}))

    elif pattern == "const":
        for fact in facts:
            if fact.name == "ConstDef":
                const_name = fact.args[0]
                bindings.append(Binding({binding_name: const_name}))

    elif pattern == "mutable-config-field":
        # Iterate over FieldClassification facts with category="mutable_config"
        for fact in facts:
            if fact.name == "FieldClassification" and len(fact.args) == 6:
                # FieldClassification(struct_type, field_path, category, negative, confidence, reason)
                struct_type, field_path, category, negative = fact.args[0], fact.args[1], fact.args[2], fact.args[3]
                # Only match positive mutable_config classifications
                if category == "mutable_config" and not negative:
                    # Bind as tuple for unpacking in filter clause
                    bindings.append(Binding({binding_name: (struct_type, field_path)}))

    elif pattern == "writes-protocol-invariant":
        # Iterate over WritesProtocolInvariant facts: (func_name, struct_type, field_path)
        for fact in facts:
            if fact.name == "WritesProtocolInvariant":
                func_name = fact.args[0]
                struct_type = fact.args[1]
                field_path = fact.args[2]
                # Bind as triple for unpacking in filter clause
                bindings.append(Binding({binding_name: (func_name, struct_type, field_path)}))

    return bindings

from dataclasses import dataclass, field
from typing import Set, Dict, List

from core.facts import Fact


# Source types for unified tracking
SOURCE_TYPES = {"sender", "weak_random"}


@dataclass
class TaintState:
    """Tracks taint state for a function."""

    tainted_vars: Set[str] = field(default_factory=set)
    taint_sources: Dict[str, str] = field(default_factory=dict)  # var -> source param
    sanitized_vars: Set[str] = field(default_factory=set)

    # Generic tracked sources: source_type -> {var -> callee}
    tracked_vars: Dict[str, Set[str]] = field(default_factory=dict)
    tracked_sources: Dict[str, Dict[str, str]] = field(default_factory=dict)  # source_type -> {var -> callee}

    def __post_init__(self):
        # Initialize tracking for each source type
        for st in SOURCE_TYPES:
            if st not in self.tracked_vars:
                self.tracked_vars[st] = set()
            if st not in self.tracked_sources:
                self.tracked_sources[st] = {}


def propagate_taint(func_name: str, facts: List[Fact]) -> List[Fact]:
    """Run fixed-point taint propagation, return derived facts.

    Args:
        func_name: Name of function being analyzed
        facts: Base facts for this function
    """

    # Extract relevant base facts for this function
    sources = []  # TaintSource facts
    assigns = []  # Assigns facts
    call_results = []  # CallResult facts
    call_args = []  # CallArg facts
    sanitizations = []  # Sanitization facts
    tracked_source_facts = []  # TrackedSource facts (generic)
    casts_to_int = []  # CastsToInt facts (for sender -> weak_random upgrade)

    for f in facts:
        if f.args[0] != func_name:
            continue
        if f.name == "TaintSource":
            sources.append(f)
        elif f.name == "Assigns":
            assigns.append(f)
        elif f.name == "CallResult":
            call_results.append(f)
        elif f.name == "CallArg":
            call_args.append(f)
        elif f.name in ("SanitizedByAssert", "SanitizedByAbortCheck", "SanitizedByClamping"):
            sanitizations.append(f)
        elif f.name == "TrackedSource":
            tracked_source_facts.append(f)
        elif f.name == "CastsToInt":
            casts_to_int.append(f)

    # Initialize state
    state = TaintState()

    # Initialize taint from sources
    for f in sources:
        param_name = f.args[1]
        state.tainted_vars.add(param_name)
        state.taint_sources[param_name] = param_name

    # Collect sanitized variables
    for f in sanitizations:
        if f.name == "SanitizedByClamping":
            # SanitizedByClamping(func, stmt_id, result_var, input_var)
            result_var = f.args[2]
            state.sanitized_vars.add(result_var)
        else:
            # SanitizedByAssert/SanitizedByAbortCheck(func, stmt_id, var)
            var = f.args[2]
            state.sanitized_vars.add(var)

    # Initialize from TrackedSource facts
    # TrackedSource(func, stmt_id, result_var, source_type, callee)
    for f in tracked_source_facts:
        _, _, result_var, source_type, callee = f.args
        if source_type in SOURCE_TYPES:
            state.tracked_vars[source_type].add(result_var)
            state.tracked_sources[source_type][result_var] = callee

    # Build map of variables that are cast to int (for sender -> weak_random upgrade)
    # CastsToInt(func, stmt_id, target_var, (source_vars))
    cast_to_int_vars = {}  # target_var -> set of source_vars
    all_vars_cast_to_int = set()  # All vars that appear in any cast to int
    for f in casts_to_int:
        _, stmt_id, target_var, source_vars = f.args
        if target_var not in cast_to_int_vars:
            cast_to_int_vars[target_var] = set()
        cast_to_int_vars[target_var].update(source_vars)
        all_vars_cast_to_int.update(source_vars)

    # Fixed-point iteration
    changed = True
    while changed:
        changed = False

        # Rule 1: Assignment propagation
        for f in assigns:
            _, stmt_id, lhs, rhs_vars = f.args
            for rhs_var in rhs_vars:
                # Taint propagation
                if rhs_var in state.tainted_vars and lhs not in state.tainted_vars:
                    state.tainted_vars.add(lhs)
                    state.taint_sources[lhs] = state.taint_sources.get(rhs_var, rhs_var)
                    changed = True

                # Sanitization propagation
                if rhs_var in state.sanitized_vars and lhs not in state.sanitized_vars:
                    state.sanitized_vars.add(lhs)
                    changed = True

                # Generic tracked source propagation
                for source_type in SOURCE_TYPES:
                    tracked = state.tracked_vars[source_type]
                    sources_map = state.tracked_sources[source_type]
                    if rhs_var in tracked and lhs not in tracked:
                        # Check if we should upgrade sender -> weak_random due to int cast
                        if source_type == "sender" and lhs in cast_to_int_vars and rhs_var in cast_to_int_vars[lhs]:
                            # This assignment casts sender to int -> upgrade to weak_random
                            weak_random_tracked = state.tracked_vars["weak_random"]
                            weak_random_sources = state.tracked_sources["weak_random"]
                            if lhs not in weak_random_tracked:
                                weak_random_tracked.add(lhs)
                                weak_random_sources[lhs] = sources_map.get(rhs_var, rhs_var)
                                changed = True
                        else:
                            tracked.add(lhs)
                            sources_map[lhs] = sources_map.get(rhs_var, rhs_var)
                            changed = True

        # Rule 2: Call result propagation
        for cr in call_results:
            _, stmt_id, result_var, callee = cr.args

            # Propagate taint through calls
            if result_var not in state.tainted_vars:
                for ca in call_args:
                    if ca.args[1] == stmt_id:
                        arg_vars = ca.args[4]
                        for av in arg_vars:
                            if av in state.tainted_vars:
                                state.tainted_vars.add(result_var)
                                state.taint_sources[result_var] = state.taint_sources.get(av, av)
                                changed = True
                                break

            # Generic tracked source propagation through calls
            for source_type in SOURCE_TYPES:
                tracked = state.tracked_vars[source_type]
                sources_map = state.tracked_sources[source_type]
                if result_var not in tracked:
                    for ca in call_args:
                        if ca.args[1] == stmt_id:
                            arg_vars = ca.args[4]
                            for av in arg_vars:
                                if av in tracked:
                                    tracked.add(result_var)
                                    sources_map[result_var] = sources_map.get(av, av)
                                    changed = True
                                    break

    # Generate derived facts
    derived = []

    # Taint facts
    for var in state.tainted_vars:
        source = state.taint_sources.get(var, var)
        derived.append(Fact("Tainted", (func_name, var)))
        if source != var:
            derived.append(Fact("TaintedBy", (func_name, var, source)))

    # Sanitized facts
    for var in state.sanitized_vars:
        derived.append(Fact("Sanitized", (func_name, var)))

    # Generic tracked derived facts
    for source_type in SOURCE_TYPES:
        tracked = state.tracked_vars[source_type]
        sources_map = state.tracked_sources[source_type]
        for var in tracked:
            callee = sources_map.get(var, "")
            # Upgrade sender -> weak_random if the var was cast to int
            effective_type = source_type
            if source_type == "sender" and var in all_vars_cast_to_int:
                effective_type = "weak_random"
            derived.append(Fact("TrackedDerived", (func_name, var, effective_type)))
            if callee:
                derived.append(Fact("TrackedDerivedFrom", (func_name, var, effective_type, callee)))

    return derived


def analyze_sink_reachability(func_name: str, facts: List[Fact]) -> List[Fact]:
    """Determine which tainted vars reach which sinks."""
    derived = []

    # Get tainted vars
    tainted = {f.args[1] for f in facts if f.name == "Tainted" and f.args[0] == func_name}
    taint_sources = {f.args[1]: f.args[2] for f in facts if f.name == "TaintedBy" and f.args[0] == func_name}

    # Get sanitized vars
    sanitized = {f.args[1] for f in facts if f.name == "Sanitized" and f.args[0] == func_name}

    # Check each sink
    for f in facts:
        if f.args[0] != func_name:
            continue

        if f.name == "SinkUsesVar":
            _, stmt_id, var, role = f.args
            if var in tainted:
                source = taint_sources.get(var, var)
                is_sanitized = var in sanitized or source in sanitized

                # Determine sink_type based on sink fact and role
                sink_type = "generic"
                for sf in facts:
                    if sf.args[0] == func_name and sf.args[1] == stmt_id:
                        if sf.name == "TransferSink":
                            if role == "recipient":
                                sink_type = "transfer_recipient"
                            elif role == "transfer_value":
                                sink_type = "transfer_value"
                        elif sf.name == "StateWriteSink":
                            sink_type = "state_write"
                        elif sf.name == "AmountExtractionSink" and role == "amount":
                            sink_type = "amount_extraction"
                        elif sf.name == "ObjectDestroySink" and role == "destroyed_object":
                            sink_type = "object_destroy"
                        elif sf.name == "LoopBoundSink" and role == "loop_bound":
                            sink_type = "loop_bound"
                        elif sf.name == "EventEmitSink" and role == "event_field":
                            sink_type = "event_field"

                # Emit parameterized facts
                derived.append(Fact("TaintedAtSink", (func_name, source, stmt_id, sink_type, role)))
                if is_sanitized:
                    derived.append(Fact("SanitizedAtSink", (func_name, source, stmt_id, sink_type, role)))

        # Track tainted amount extractions from LetStmt patterns
        if f.name == "AmountExtraction":
            _, stmt_id, result_var, amount_var = f.args
            if amount_var in tainted:
                source = taint_sources.get(amount_var, amount_var)
                is_sanitized = amount_var in sanitized or source in sanitized
                derived.append(Fact("TaintedAtSink", (func_name, source, stmt_id, "amount_extraction", "")))
                if is_sanitized:
                    derived.append(Fact("SanitizedAtSink", (func_name, source, stmt_id, "amount_extraction", "")))

    return derived

"""
Transfer-related fact generation: Transfers, zero-address transfers.
"""

from typing import Set, Dict, List

from core.context import ProjectContext
from core.facts import Fact
from core.utils import debug, get_simple_name
from move.sui_patterns import ALL_TRANSFER_SINKS


ZERO_ADDRESS_VALUES = {"@0x0", "@0x00", "@0", "0x0", "0x00"}


def generate_transfers_facts(ctx: ProjectContext) -> None:
    """
    Generate Transfers facts (structural, not LLM).
    For each function, checks if it calls transfer::* functions.
    """
    transfers_count = 0

    for source_file in ctx.source_files.values():
        func_calls: dict[str, set[str]] = {}

        for fact in source_file.facts:
            if fact.name == "InFun" and "@" in fact.args[1]:
                func_name = fact.args[0]
                call_id = fact.args[1]
                callee = call_id.split("@")[0]
                if func_name not in func_calls:
                    func_calls[func_name] = set()
                func_calls[func_name].add(callee)

        for func_name, callees in func_calls.items():
            for callee in callees:
                callee_simple = get_simple_name(callee)
                is_transfer = (
                    callee in ALL_TRANSFER_SINKS
                    or callee_simple
                    in {
                        "transfer",
                        "public_transfer",
                        "share_object",
                        "public_share_object",
                        "freeze_object",
                        "public_freeze_object",
                    }
                    or any(callee.endswith(t) for t in ALL_TRANSFER_SINKS)
                )
                if is_transfer:
                    transfers_fact = Fact("Transfers", (func_name, True))
                    if not any(f.name == "Transfers" and f.args[0] == func_name for f in source_file.facts):
                        source_file.facts.append(transfers_fact)
                        transfers_count += 1
                        debug(f"  Transfers({func_name}) [structural]")
                    if func_name in ctx.global_facts_index:
                        for file_path, func_facts in ctx.global_facts_index[func_name].items():
                            if not any(f.name == "Transfers" and f.args[0] == func_name for f in func_facts):
                                func_facts.append(transfers_fact)
                    break

    if transfers_count > 0:
        debug(f"Generated {transfers_count} structural Transfers facts")


def generate_value_extraction_facts(ctx: ProjectContext) -> None:
    """
    Generate HasValueExtraction facts (structural).
    For each function, checks if it has AmountExtractionSink or ValueExtractionSink.
    """
    extraction_count = 0

    for source_file in ctx.source_files.values():
        funcs_with_extraction: set[str] = set()

        for fact in source_file.facts:
            if fact.name in ("AmountExtractionSink", "ValueExtractionSink"):
                funcs_with_extraction.add(fact.args[0])

        for func_name in funcs_with_extraction:
            extraction_fact = Fact("HasValueExtraction", (func_name, True))
            if not any(f.name == "HasValueExtraction" and f.args[0] == func_name for f in source_file.facts):
                source_file.facts.append(extraction_fact)
                extraction_count += 1
                debug(f"  HasValueExtraction({func_name}) [structural]")
                if func_name in ctx.global_facts_index:
                    for file_path, func_facts in ctx.global_facts_index[func_name].items():
                        if not any(f.name == "HasValueExtraction" and f.args[0] == func_name for f in func_facts):
                            func_facts.append(extraction_fact)

    if extraction_count > 0:
        debug(f"Generated {extraction_count} structural HasValueExtraction facts")


def detect_zero_address_transfers(ctx: ProjectContext) -> None:
    """
    Detect transfers where recipient is a zero address (constant or direct literal).
    Patterns:
    1. transfer::public_transfer(obj, ZERO_ACCOUNT) where ZERO_ACCOUNT = @0x0
    2. transfer::public_transfer(obj, @0x0)  // direct literal
    """
    zero_transfer_count = 0

    for source_file in ctx.source_files.values():
        # Collect zero address constants
        zero_constants: Set[str] = set()
        for fact in source_file.facts:
            if fact.name == "ConstDef":
                _, simple_name, value, const_type = fact.args
                if const_type == "address" and str(value) in ZERO_ADDRESS_VALUES:
                    zero_constants.add(simple_name)

        # Check for zero address transfers via constants
        for fact in source_file.facts:
            if fact.name == "SinkUsesVar" and fact.args[3] == "recipient":
                func_name, stmt_id, var, _ = fact.args
                if var in zero_constants:
                    zero_transfer_fact = Fact("TransfersToZeroAddress", (func_name, stmt_id, var))
                    if not any(
                        f.name == "TransfersToZeroAddress" and f.args[0] == func_name for f in source_file.facts
                    ):
                        source_file.facts.append(zero_transfer_fact)
                        zero_transfer_count += 1
                        debug(f"  TransfersToZeroAddress({func_name}) via {var}")

                    if func_name in ctx.global_facts_index:
                        for file_path, func_facts in ctx.global_facts_index[func_name].items():
                            if not any(
                                f.name == "TransfersToZeroAddress" and f.args[0] == func_name for f in func_facts
                            ):
                                func_facts.append(zero_transfer_fact)

        # Also check for direct @0x0 literals in transfer calls
        # ActualArg(transfer_call_id, arg_idx, arg_value)
        transfer_calls: Dict[str, List[tuple]] = {}  # call_id -> [(arg_idx, arg_value)]
        for fact in source_file.facts:
            if fact.name == "ActualArg":
                call_id, arg_idx, arg_value = fact.args
                if "transfer::public_transfer" in call_id or "transfer::transfer" in call_id:
                    if call_id not in transfer_calls:
                        transfer_calls[call_id] = []
                    transfer_calls[call_id].append((arg_idx, arg_value))

        # Check if arg_idx 1 (recipient) is a zero address literal OR zero constant
        for call_id, args in transfer_calls.items():
            for arg_idx, arg_value in args:
                is_zero = str(arg_value) in ZERO_ADDRESS_VALUES or arg_value in zero_constants
                if arg_idx == 1 and is_zero:
                    # Find which function this call belongs to
                    func_name = None
                    for fact in source_file.facts:
                        if fact.name == "InFun" and fact.args[1] == call_id:
                            func_name = fact.args[0]
                            break

                    if func_name:
                        zero_transfer_fact = Fact("TransfersToZeroAddress", (func_name, call_id, arg_value))
                        if not any(
                            f.name == "TransfersToZeroAddress" and f.args[0] == func_name for f in source_file.facts
                        ):
                            source_file.facts.append(zero_transfer_fact)
                            zero_transfer_count += 1
                            debug(f"  TransfersToZeroAddress({func_name}) via direct literal {arg_value}")

                            if func_name in ctx.global_facts_index:
                                for file_path, func_facts in ctx.global_facts_index[func_name].items():
                                    if not any(
                                        f.name == "TransfersToZeroAddress" and f.args[0] == func_name
                                        for f in func_facts
                                    ):
                                        func_facts.append(zero_transfer_fact)

    if zero_transfer_count > 0:
        debug(f"Generated {zero_transfer_count} TransfersToZeroAddress facts")

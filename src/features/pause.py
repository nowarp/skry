from typing import List, Dict, Any, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from core.context import ProjectContext

from features.base import FeatureDetector, FeatureContext
from core.facts import Fact
from core.utils import debug, get_simple_name
from prompts import render as render_prompt


# Limits to prevent prompt explosion
MAX_STRUCTS = 5
MAX_FUNCTIONS = 15
MAX_BOOL_FIELDS = 10


class PauseDetector(FeatureDetector):
    """Detect global pause mechanism patterns."""

    name = "pause"

    # Keywords for pause-related functions
    PAUSE_FUNC_KEYWORDS = {
        "pause",
        "unpause",
        "set_paused",
        "set_pause",
        "emergency",
        "halt",
        "stop",
        "freeze",
        "unfreeze",
    }

    # Keywords for pause-related fields
    PAUSE_FIELD_KEYWORDS = {
        "paused",
        "is_paused",
        "pause",
        "halted",
        "is_halted",
        "emergency",
        "stopped",
        "frozen",
        "is_frozen",
    }

    def heuristic_score(self, ctx: "ProjectContext") -> float:
        """
        Quick structural check for pause presence.

        Scoring:
        - Bool field with pause-like name in shared/config struct: +0.4
        - Function with pause-like name: +0.3
        - Constant with PAUSED/E_PAUSED: +0.2
        - Multiple functions reading same bool field: +0.3
        """
        score = 0.0
        found_pause_field = False
        found_pause_func = False
        found_pause_const = False

        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                # Check for bool fields with pause-like names
                if fact.name == "StructField" and len(fact.args) >= 4:
                    field_name = str(fact.args[2]).lower()
                    field_type = str(fact.args[3]).lower()
                    if field_type == "bool" and any(kw in field_name for kw in self.PAUSE_FIELD_KEYWORDS):
                        found_pause_field = True
                        debug(f"  [pause] Found pause-like field: {fact.args[0]}.{fact.args[2]}")

                # Check function names
                if fact.name == "Fun":
                    func_name = get_simple_name(fact.args[0]).lower()
                    if any(kw in func_name for kw in self.PAUSE_FUNC_KEYWORDS):
                        found_pause_func = True
                        debug(f"  [pause] Found pause-like function: {fact.args[0]}")

                # Check constants
                if fact.name == "ConstDef":
                    const_name = fact.args[1].lower()
                    if "pause" in const_name or "e_paused" in const_name:
                        found_pause_const = True
                        debug(f"  [pause] Found pause constant: {fact.args[1]}")

        if found_pause_field:
            score += 0.4
        if found_pause_func:
            score += 0.3
        if found_pause_const:
            score += 0.2

        return min(score, 1.0)

    def build_context(self, ctx: "ProjectContext") -> FeatureContext:
        """
        Collect pause-related code for LLM analysis.

        Prioritize:
        1. Shared/config structs with bool fields
        2. Functions with pause-like names
        3. Functions that read bool fields in conditions
        """
        relevant_structs: List[Dict[str, Any]] = []
        relevant_functions: List[Dict[str, Any]] = []
        relevant_constants: List[Dict[str, Any]] = []

        # Track structs with bool fields
        structs_with_bool: Dict[str, List[str]] = {}  # struct -> [field_names]

        # First pass: find bool fields in structs
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "StructField" and len(fact.args) >= 4:
                    struct_name = fact.args[0]
                    field_name = fact.args[2]
                    field_type = str(fact.args[3]).lower()
                    if field_type == "bool":
                        if struct_name not in structs_with_bool:
                            structs_with_bool[struct_name] = []
                        structs_with_bool[struct_name].append(field_name)

        # Second pass: collect structs, prioritize shared/config
        seen_structs: Set[str] = set()
        shared_structs: Set[str] = set()
        config_structs: Set[str] = set()

        # Identify shared and config structs
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "IsSharedObject":
                    shared_structs.add(fact.args[0])
                if fact.name == "IsConfig":
                    config_structs.add(fact.args[0])

        # Collect structs with bool fields, prioritizing shared/config
        priority_structs = []
        other_structs = []

        for file_path, file_ctx in ctx.source_files.items():
            for fact in file_ctx.facts:
                if fact.name == "Struct":
                    struct_name = fact.args[0]
                    if struct_name in seen_structs:
                        continue
                    if struct_name not in structs_with_bool:
                        continue

                    source = self._get_struct_source_with_comment(file_ctx, struct_name)
                    if not source:
                        continue

                    struct_info = {
                        "name": struct_name,
                        "source": source,
                        "bool_fields": structs_with_bool[struct_name],
                        "is_shared": struct_name in shared_structs,
                        "is_config": struct_name in config_structs,
                    }

                    if struct_name in shared_structs or struct_name in config_structs:
                        priority_structs.append(struct_info)
                    else:
                        # Check if name suggests config/settings
                        simple_name = get_simple_name(struct_name).lower()
                        if any(kw in simple_name for kw in ["config", "settings", "state", "global", "protocol"]):
                            priority_structs.append(struct_info)
                        else:
                            other_structs.append(struct_info)

                    seen_structs.add(struct_name)

        # Combine with priority
        relevant_structs = priority_structs[:MAX_STRUCTS]
        remaining = MAX_STRUCTS - len(relevant_structs)
        if remaining > 0:
            relevant_structs.extend(other_structs[:remaining])

        # Collect pause-related functions (with bodies for analysis)
        seen_functions: Set[str] = set()
        pause_named_funcs = []
        bool_field_readers = []

        # First, collect functions with pause-like names
        for file_path, file_ctx in ctx.source_files.items():
            for fact in file_ctx.facts:
                if fact.name == "Fun":
                    func_name = fact.args[0]
                    if func_name in seen_functions:
                        continue

                    simple_name = get_simple_name(func_name).lower()
                    if any(kw in simple_name for kw in self.PAUSE_FUNC_KEYWORDS):
                        args = self._get_function_args(file_ctx.facts, func_name)
                        is_admin = self._function_requires_cap(file_ctx.facts, func_name)

                        # Get function source to show body for LLM analysis
                        from move.extract import extract_function_source

                        func_source = None
                        if file_ctx.root and file_ctx.source_code:
                            func_source = extract_function_source(file_ctx.source_code, func_name, file_ctx.root)

                        pause_named_funcs.append(
                            {
                                "name": func_name,
                                "signature": f"fun {get_simple_name(func_name)}({', '.join(args)})",
                                "requires_cap": is_admin,
                                "source": func_source,
                            }
                        )
                        seen_functions.add(func_name)

        # Also collect some functions that read bool fields from potential pause structs
        # This helps LLM identify pause check patterns
        for struct_name in structs_with_bool:
            if struct_name not in shared_structs and struct_name not in config_structs:
                simple_name = get_simple_name(struct_name).lower()
                if not any(kw in simple_name for kw in ["config", "settings", "state", "global", "protocol"]):
                    continue

            for file_path, file_ctx in ctx.source_files.items():
                for fact in file_ctx.facts:
                    if fact.name == "ReadsField" and len(fact.args) >= 3:
                        func_name = fact.args[0]
                        read_struct = fact.args[1]
                        read_field = fact.args[2]

                        if func_name in seen_functions or read_struct != struct_name:
                            continue
                        if read_field not in structs_with_bool[struct_name]:
                            continue

                        args = self._get_function_args(file_ctx.facts, func_name)
                        is_admin = self._function_requires_cap(file_ctx.facts, func_name)

                        from move.extract import extract_function_source

                        func_source = None
                        if file_ctx.root and file_ctx.source_code:
                            func_source = extract_function_source(file_ctx.source_code, func_name, file_ctx.root)

                        bool_field_readers.append(
                            {
                                "name": func_name,
                                "signature": f"fun {get_simple_name(func_name)}({', '.join(args)})",
                                "requires_cap": is_admin,
                                "source": func_source,
                            }
                        )
                        seen_functions.add(func_name)

                        if len(bool_field_readers) >= 5:
                            break
                if len(bool_field_readers) >= 5:
                    break

        # Combine: prioritize pause-named functions, then bool field readers
        relevant_functions = pause_named_funcs[:MAX_FUNCTIONS]
        remaining = MAX_FUNCTIONS - len(relevant_functions)
        if remaining > 0:
            relevant_functions.extend(bool_field_readers[:remaining])

        # Collect pause-related constants
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "ConstDef" and len(relevant_constants) < 5:
                    const_name = fact.args[1].lower()
                    if "pause" in const_name:
                        relevant_constants.append(
                            {
                                "name": fact.args[1],
                                "value": fact.args[2] if len(fact.args) > 2 else "?",
                                "type": fact.args[3] if len(fact.args) > 3 else "?",
                            }
                        )

        return FeatureContext(
            project_name=self._get_project_name(ctx),
            relevant_structs=relevant_structs,
            relevant_functions=relevant_functions,
            relevant_constants=relevant_constants,
        )

    def _function_requires_cap(self, facts: List[Fact], func_name: str) -> bool:
        """Check if function has a capability parameter."""
        for fact in facts:
            if fact.name == "FormalArg" and fact.args[0] == func_name:
                param_type = str(fact.args[3])
                if "Cap" in param_type or "Admin" in param_type:
                    return True
        return False

    def get_llm_prompt(self, feature_ctx: FeatureContext) -> str:
        """Build prompt for global pause detection."""
        return render_prompt(
            "features/pause.j2",
            project_name=feature_ctx.project_name,
            structs=feature_ctx.relevant_structs,
            functions=feature_ctx.relevant_functions,
            constants=feature_ctx.relevant_constants,
        )

    def get_response_schema(self) -> Dict[str, type]:
        """Return expected JSON response schema."""
        return {
            "has_pause": bool,
            "confidence": float,
            "pause_struct": str,
            "pause_field": str,
            "check_functions": list,
            "control_functions": list,
        }

    def parse_response(self, response: Dict[str, Any], ctx: "ProjectContext") -> List[Fact]:
        """Parse LLM response into facts."""
        facts = []
        feature_name = "FeaturePause"

        has_pause = response.get("has_pause", False)
        confidence = response.get("confidence", 0.0)

        if not has_pause or confidence < 0.7:
            debug(f"[pause] No global pause or low confidence: {has_pause}, {confidence}")
            return [Fact(feature_name, (False,))]

        # Feature is present
        facts.append(Fact(feature_name, (True,)))
        debug(f"[pause] Detected global pause with confidence {confidence}")

        # Add IsGlobalPauseField fact
        pause_struct = response.get("pause_struct", "")
        pause_field = response.get("pause_field", "")
        if pause_struct and pause_field:
            facts.append(Fact("IsGlobalPauseField", (pause_struct, pause_field)))
            debug(f"[pause] IsGlobalPauseField({pause_struct}, {pause_field})")

        # Add ChecksPause facts for checking functions
        for func in response.get("check_functions", []):
            facts.append(Fact("ChecksPause", (func,)))
            debug(f"[pause] ChecksPause({func})")

        # Add IsPauseControl facts for control functions
        for func in response.get("control_functions", []):
            facts.append(Fact("IsPauseControl", (func,)))
            debug(f"[pause] IsPauseControl({func})")

        return facts

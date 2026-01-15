from typing import List, Dict, Any, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from core.context import ProjectContext

from features.base import FeatureDetector, FeatureContext
from core.facts import Fact
from core.utils import debug, get_simple_name
from prompts import render as render_prompt


# Limits to prevent prompt explosion
MAX_PRIMARY_STRUCTS = 5  # Structs with version field or "version" in name
MAX_FUNCTIONS = 20  # Version-related functions (need room for verify_* methods)
MAX_CONSTANTS = 10  # Version constants


class VersionDetector(FeatureDetector):
    """Detect Sui-style versioning patterns."""

    name = "version"

    # Only look for actual version-related functions
    VERSION_FUNC_KEYWORDS = {
        "version",
        "assert_version",
        "check_version",
        "verify_version",
        "verify_authority",
        "verify_witness",
        "migrate",
        "upgrade",
    }

    def heuristic_score(self, ctx: "ProjectContext") -> float:
        """
        Check for version-related patterns in structural facts.

        Scoring:
        - Struct with "version" in name: +0.2
        - Field named "version" with numeric type: +0.3
        - Function with version-related name: +0.3
        - Constant named VERSION: +0.2
        """
        score = 0.0
        found_version_struct = False
        found_version_field = False
        found_version_func = False
        found_version_const = False

        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                # Check struct names
                if fact.name == "Struct":
                    struct_name = fact.args[0].lower()
                    if "version" in struct_name:
                        found_version_struct = True
                        debug(f"  [version] Found version struct: {fact.args[0]}")

                # Check field names
                # StructField(struct_name, field_idx, field_name, field_type)
                if fact.name == "StructField" and len(fact.args) >= 4:
                    field_name = str(fact.args[2]).lower()
                    field_type = str(fact.args[3]).lower()
                    if field_name == "version" and ("u64" in field_type or "u32" in field_type):
                        found_version_field = True
                        debug(f"  [version] Found version field in {fact.args[0]}")

                # Check function names
                if fact.name == "Fun":
                    func_name = get_simple_name(fact.args[0]).lower()
                    if any(kw in func_name for kw in self.VERSION_FUNC_KEYWORDS):
                        found_version_func = True
                        debug(f"  [version] Found version function: {fact.args[0]}")

                # Check constants
                if fact.name == "ConstDef":
                    const_name = fact.args[1].lower()
                    if "version" in const_name:
                        found_version_const = True
                        debug(f"  [version] Found version constant: {fact.args[1]}")

        if found_version_struct:
            score += 0.2
        if found_version_field:
            score += 0.3
        if found_version_func:
            score += 0.3
        if found_version_const:
            score += 0.2

        return min(score, 1.0)

    def build_context(self, ctx: "ProjectContext") -> FeatureContext:
        """
        Collect ONLY version-related code. Prioritize:
        1. Structs with "version" in name (full source + comments)
        2. Structs with version: u64 field (full source + comments)
        3. Version-related functions (signature only)
        4. Version constants
        """
        # Priority 1: Structs with "version" in name
        version_named_structs: List[Dict[str, Any]] = []
        # Priority 2: Structs with version field
        version_field_structs: List[Dict[str, Any]] = []

        relevant_functions: List[Dict[str, Any]] = []
        relevant_constants: List[Dict[str, Any]] = []

        # Track which structs have version fields
        structs_with_version_field: Set[str] = set()

        # First pass: find structs with version fields
        # StructField(struct_name, field_idx, field_name, field_type)
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "StructField" and len(fact.args) >= 4:
                    field_name = str(fact.args[2]).lower()
                    field_type = str(fact.args[3]).lower()
                    # Only numeric version fields
                    if field_name == "version" and ("u64" in field_type or "u32" in field_type):
                        structs_with_version_field.add(fact.args[0])

        # Second pass: collect relevant code
        seen_structs: Set[str] = set()
        seen_functions: Set[str] = set()

        for file_path, file_ctx in ctx.source_files.items():
            for fact in file_ctx.facts:
                # Collect structs - ONLY version-related
                if fact.name == "Struct":
                    struct_name = fact.args[0]
                    if struct_name in seen_structs:
                        continue

                    has_version_in_name = "version" in struct_name.lower()
                    has_version_field = struct_name in structs_with_version_field

                    # Only collect if version-related
                    if has_version_in_name or has_version_field:
                        source = self._get_struct_source_with_comment(file_ctx, struct_name)
                        if source:
                            struct_info = {
                                "name": struct_name,
                                "source": source,
                                "has_version_field": has_version_field,
                            }
                            if has_version_in_name:
                                version_named_structs.append(struct_info)
                            else:
                                version_field_structs.append(struct_info)
                            seen_structs.add(struct_name)

                # Collect version-related functions (signature only)
                # Prioritize: verify_*/assert_*/check_* first, then others
                if fact.name == "Fun":
                    func_name = fact.args[0]
                    if func_name in seen_functions:
                        continue

                    simple_name = get_simple_name(func_name).lower()
                    if any(kw in simple_name for kw in self.VERSION_FUNC_KEYWORDS):
                        args = self._get_function_args(file_ctx.facts, func_name)
                        func_info = {
                            "name": func_name,
                            "signature": f"fun {get_simple_name(func_name)}({', '.join(args)})",
                            "is_check": any(p in simple_name for p in ["verify_", "assert_", "check_"]),
                        }
                        relevant_functions.append(func_info)
                        seen_functions.add(func_name)

                # Collect version constants
                if fact.name == "ConstDef" and len(relevant_constants) < MAX_CONSTANTS:
                    const_name = fact.args[1]
                    if "version" in const_name.lower():
                        relevant_constants.append(
                            {
                                "name": const_name,
                                "value": fact.args[2] if len(fact.args) > 2 else "?",
                                "type": fact.args[3] if len(fact.args) > 3 else "?",
                            }
                        )

        # Combine structs with priority (version-named first, then version-field)
        relevant_structs = version_named_structs[:MAX_PRIMARY_STRUCTS]
        remaining_slots = MAX_PRIMARY_STRUCTS - len(relevant_structs)
        if remaining_slots > 0:
            relevant_structs.extend(version_field_structs[:remaining_slots])

        # Sort functions: check functions first (verify_*, assert_*, check_*), then limit
        relevant_functions.sort(key=lambda f: (0 if f.get("is_check") else 1, f["name"]))
        relevant_functions = relevant_functions[:MAX_FUNCTIONS]

        return FeatureContext(
            project_name=self._get_project_name(ctx),
            relevant_structs=relevant_structs,
            relevant_functions=relevant_functions,
            relevant_constants=relevant_constants,
        )

    def get_llm_prompt(self, feature_ctx: FeatureContext) -> str:
        """Build concise prompt for version detection."""
        return render_prompt(
            "features/version.j2",
            project_name=feature_ctx.project_name,
            structs=feature_ctx.relevant_structs,
            functions=feature_ctx.relevant_functions,
            constants=feature_ctx.relevant_constants,
        )

    def get_response_schema(self) -> Dict[str, type]:
        """Return expected JSON response schema.

        Note: "reason" field is automatically added when SKRY_LLM_DEBUG=1.
        """
        return {
            "has_versioning": bool,
            "confidence": float,
            "version_struct": str,
            "version_check_functions": list,
            "version_check_methods": list,
        }

    def parse_response(self, response: Dict[str, Any], ctx: "ProjectContext") -> List[Fact]:
        """Parse LLM response dict into facts."""
        facts = []
        feature_name = "FeatureVersion"

        # Check confidence and result
        has_versioning = response.get("has_versioning", False)
        confidence = response.get("confidence", 0.0)

        if not has_versioning or confidence < 0.7:
            debug(f"[version] No versioning or low confidence: {has_versioning}, {confidence}")
            return [Fact(feature_name, (False,))]

        # Feature is present
        facts.append(Fact(feature_name, (True,)))
        debug(f"[version] Detected versioning with confidence {confidence}")

        # Add IsVersion fact for the version struct
        version_struct = response.get("version_struct")
        if version_struct:
            facts.append(Fact("IsVersion", (version_struct,)))
            debug(f"[version] IsVersion({version_struct})")

        # Add HasVersionCheck facts for checking functions
        for func in response.get("version_check_functions", []):
            facts.append(Fact("HasVersionCheck", (func,)))
            debug(f"[version] HasVersionCheck({func})")

        # Add IsVersionCheckMethod facts for method names
        for method in response.get("version_check_methods", []):
            facts.append(Fact("IsVersionCheckMethod", (method,)))
            debug(f"[version] IsVersionCheckMethod({method})")

        return facts

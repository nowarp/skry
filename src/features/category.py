"""
Project category detector.

Classifies projects into categories to enable/disable relevant rules.
Categories are mutually non-exclusive - a project can have multiple categories.

Emits facts:
- ProjectCategory(category, probability): For each category with probability >= 0.7
"""

from typing import List, Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from core.context import ProjectContext

from features.base import FeatureDetector, FeatureContext
from core.facts import Fact, PROJECT_CATEGORIES
from core.utils import debug, get_simple_name
from prompts import render as render_prompt


# Limits for prompt size
MAX_MODULES = 15
MAX_STRUCTS = 25
MAX_FUNCTIONS = 40
MAX_EVENTS = 15

# Probability threshold for emitting category facts
CATEGORY_PROBABILITY_THRESHOLD = 0.7


class CategoryDetector(FeatureDetector):
    """Detect project category for rule filtering."""

    name = "category"

    def heuristic_score(self, ctx: "ProjectContext") -> float:
        """
        Always return 0.5 to trigger LLM classification.
        We can't reliably classify projects without LLM.
        """
        return 0.5

    def build_context(self, ctx: "ProjectContext") -> FeatureContext:
        """
        Collect high-level project overview:
        - Module names
        - Struct names and key fields
        - Public function signatures
        - Event names
        """
        modules: List[str] = []
        structs: List[Dict[str, Any]] = []
        functions: List[Dict[str, Any]] = []
        events: List[str] = []

        seen_modules: set[str] = set()
        seen_structs: set[str] = set()
        seen_functions: set[str] = set()
        seen_events: set[str] = set()

        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                # Collect module names from function paths
                if fact.name == "Fun":
                    func_name = fact.args[0]
                    parts = func_name.split("::")
                    if len(parts) >= 2:
                        module = "::".join(parts[:-1])
                        if module not in seen_modules and len(modules) < MAX_MODULES:
                            modules.append(module)
                            seen_modules.add(module)

                # Collect struct names
                if fact.name == "Struct":
                    struct_name = fact.args[0]
                    if struct_name not in seen_structs and len(structs) < MAX_STRUCTS:
                        simple_name = get_simple_name(struct_name)
                        structs.append({"name": simple_name, "full_name": struct_name})
                        seen_structs.add(struct_name)

                # Collect public function signatures
                if fact.name == "Fun":
                    func_name = fact.args[0]
                    if func_name in seen_functions:
                        continue

                    # Check if public or entry
                    is_public = any(f.name == "IsPublic" and f.args[0] == func_name for f in file_ctx.facts)
                    is_entry = any(f.name == "IsEntry" and f.args[0] == func_name for f in file_ctx.facts)

                    if (is_public or is_entry) and len(functions) < MAX_FUNCTIONS:
                        args = self._get_function_args(file_ctx.facts, func_name, include_names=False)
                        ret_type = self._get_return_type(file_ctx.facts, func_name)
                        simple_name = get_simple_name(func_name)
                        sig = f"{simple_name}({', '.join(args)})"
                        if ret_type:
                            sig += f": {ret_type}"
                        functions.append(
                            {
                                "name": simple_name,
                                "signature": sig,
                                "is_entry": is_entry,
                            }
                        )
                        seen_functions.add(func_name)

                # Collect event names
                if fact.name == "IsEvent":
                    event_name = fact.args[0]
                    if event_name not in seen_events and len(events) < MAX_EVENTS:
                        simple_name = get_simple_name(event_name)
                        events.append(simple_name)
                        seen_events.add(event_name)

        # Sort for consistent output
        modules.sort()
        structs.sort(key=lambda s: s["name"])
        functions.sort(key=lambda f: f["name"])
        events.sort()

        return FeatureContext(
            project_name=self._get_project_name(ctx),
            relevant_structs=structs,
            relevant_functions=functions,
            relevant_constants=[{"events": events, "modules": modules}],
        )

    def _get_return_type(self, facts: List[Fact], func_name: str) -> str | None:
        """Get function return type from FunReturnType fact."""
        for fact in facts:
            if fact.name == "FunReturnType" and fact.args[0] == func_name:
                return fact.args[1]
        return None

    def get_llm_prompt(self, feature_ctx: FeatureContext) -> str:
        """Build prompt for project classification."""
        extra = feature_ctx.relevant_constants[0] if feature_ctx.relevant_constants else {}
        modules = extra.get("modules", [])
        events = extra.get("events", [])

        return render_prompt(
            "features/category.j2",
            project_name=feature_ctx.project_name,
            modules=modules,
            structs=feature_ctx.relevant_structs,
            functions=feature_ctx.relevant_functions,
            events=events,
        )

    def get_response_schema(self) -> Dict[str, type]:
        """Return expected JSON response schema."""
        return {
            "categories": list,  # List of {"category": str, "probability": float}
        }

    def parse_response(self, response: Dict[str, Any], ctx: "ProjectContext") -> List[Fact]:
        """Parse LLM response into ProjectCategory facts."""
        facts = []
        categories = response.get("categories", [])

        for cat_info in categories:
            if not isinstance(cat_info, dict):
                continue

            category = cat_info.get("category", "")
            probability = cat_info.get("probability", 0.0)

            # Validate category name
            if category not in PROJECT_CATEGORIES:
                debug(f"[category] Unknown category '{category}', skipping")
                continue

            # Only emit if probability >= threshold
            if probability >= CATEGORY_PROBABILITY_THRESHOLD:
                facts.append(Fact("ProjectCategory", (category, probability)))
                debug(f"[category] ProjectCategory({category}, {probability:.2f})")
            else:
                debug(
                    f"[category] {category} probability {probability:.2f} < {CATEGORY_PROBABILITY_THRESHOLD}, skipping"
                )

        if not facts:
            debug("[category] No categories above threshold")

        return facts

    def detect(self, ctx: "ProjectContext") -> List[Fact]:
        """
        Override base detect() - we don't require relevant_structs.
        """
        feature_ctx = self.build_context(ctx)

        # Need at least some functions or structs
        if not feature_ctx.relevant_functions and not feature_ctx.relevant_structs:
            debug("[category] No functions or structs found, skipping classification")
            return []

        prompt = self.get_llm_prompt(feature_ctx)
        schema = self.get_response_schema()

        from llm.client import call_llm_json

        response = call_llm_json(prompt, schema, context=self.name)

        if "error" in response:
            from core.utils import warn

            warn(f"[category] LLM error: {response['error']}")
            return []

        debug(f"[category] LLM response: {response}")

        return self.parse_response(response, ctx)

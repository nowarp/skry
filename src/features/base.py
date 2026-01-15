"""
Base class for feature detectors.

Feature detectors analyze project-level patterns using:
1. Heuristics on structural facts (fast, cheap)
2. LLM reasoning when heuristics are uncertain (slower, costs money)

The detection flow:
1. heuristic_score() -> 0.0 to 1.0
2. If score < 0.1: return negative fact immediately
3. If score > 0.9: use heuristics but still get details from LLM
4. Otherwise: build context and ask LLM
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from core.context import ProjectContext

from core.facts import Fact
from core.utils import debug, warn
from move.extract import extract_struct_source


@dataclass
class FeatureContext:
    """
    Curated code snippets for LLM analysis.

    Contains only the relevant parts of the codebase for a specific
    feature detection task, minimizing token usage.
    """

    project_name: str
    relevant_structs: List[Dict[str, Any]] = field(default_factory=list)
    relevant_functions: List[Dict[str, Any]] = field(default_factory=list)
    relevant_constants: List[Dict[str, Any]] = field(default_factory=list)


class FeatureDetector(ABC):
    """
    Abstract base class for feature detection.

    Subclasses must implement:
    - name: Feature identifier (e.g., "version", "acl")
    - heuristic_score(): Quick structural check
    - build_context(): Extract relevant code for LLM
    - get_llm_prompt(): Build structured prompt
    - get_response_schema(): Return expected JSON schema
    - parse_response(): Parse LLM response dict into facts
    """

    name: str = "unknown"

    @abstractmethod
    def heuristic_score(self, ctx: "ProjectContext") -> float:
        """
        Quick structural check for feature presence.

        Returns:
            0.0: Feature definitely NOT present
            0.1-0.3: Unlikely, but ask LLM to be sure
            0.4-0.6: Uncertain, need LLM
            0.7-0.9: Likely, ask LLM for details
            1.0: Feature definitely present (still ask LLM for details)
        """
        pass

    @abstractmethod
    def build_context(self, ctx: "ProjectContext") -> FeatureContext:
        """
        Extract relevant code snippets for LLM analysis.

        Should collect only the code relevant to this feature,
        minimizing token usage while providing enough context.
        """
        pass

    @abstractmethod
    def get_llm_prompt(self, feature_ctx: FeatureContext) -> str:
        """
        Build a structured prompt for LLM.

        Should:
        - Explain the feature pattern clearly
        - Provide the relevant code
        - Request JSON response with specific schema
        """
        pass

    @abstractmethod
    def get_response_schema(self) -> Dict[str, type]:
        """
        Return expected JSON response schema for call_llm_json.

        Example: {"has_versioning": bool, "confidence": float, "version_struct": str}
        """
        pass

    @abstractmethod
    def parse_response(self, response: Dict[str, Any], ctx: "ProjectContext") -> List[Fact]:
        """
        Parse LLM response dict into facts.

        Args:
            response: Parsed JSON response from LLM (already validated against schema)
            ctx: Project context

        Returns:
            List of facts to add to project
        """
        pass

    def detect(self, ctx: "ProjectContext") -> List[Fact]:
        """
        Main detection logic.

        Flow:
        1. Run heuristic check
        2. If confident negative (< 0.1), return negative fact
        3. Build context - if no relevant structs, return negative
        4. Otherwise, ask LLM for details
        """
        score = self.heuristic_score(ctx)
        feature_name = f"Feature{self.name.title()}"

        debug(f"FeatureDetector[{self.name}]: heuristic_score={score:.2f}")

        # Confident negative - don't waste LLM tokens
        if score < 0.1:
            debug(f"FeatureDetector[{self.name}]: score < 0.1, returning False")
            return [Fact(feature_name, (False,))]

        # Build context
        feature_ctx = self.build_context(ctx)

        # No relevant structs = no feature. Functions alone are not enough.
        if not feature_ctx.relevant_structs:
            debug(f"FeatureDetector[{self.name}]: no relevant structs, returning False")
            return [Fact(feature_name, (False,))]

        prompt = self.get_llm_prompt(feature_ctx)
        schema = self.get_response_schema()

        from llm.client import call_llm_json

        response = call_llm_json(prompt, schema, context=self.name)

        if "error" in response:
            warn(f"FeatureDetector[{self.name}]: LLM error: {response['error']}")
            # Fallback to heuristic result
            return [Fact(feature_name, (score > 0.5,))]

        debug(f"FeatureDetector[{self.name}]: LLM response: {response}")

        return self.parse_response(response, ctx)

    def _get_project_name(self, ctx: "ProjectContext") -> str:
        """Extract project name from source paths."""
        if ctx.source_files:
            first_path = next(iter(ctx.source_files.keys()))
            parts = first_path.split("/")
            # Look for "sources" directory and get parent
            for i, p in enumerate(parts):
                if p == "sources" and i > 0:
                    return parts[i - 1]
            # Fallback: use last directory name before file
            if len(parts) >= 2:
                return parts[-2]
        return "unknown"

    def _get_struct_source_with_comment(self, file_ctx, struct_name: str) -> str | None:
        """Extract struct source code with its doc comment."""
        if file_ctx.root is None:
            return None

        source = extract_struct_source(file_ctx.source_code, struct_name, file_ctx.root)
        if not source:
            return None

        comment = None
        for fact in file_ctx.facts:
            if fact.name == "StructComment" and fact.args[0] == struct_name:
                comment = fact.args[1]
                break

        if comment:
            return f"{comment}\n{source}"
        return source

    def _get_function_args(self, facts: List[Fact], func_name: str, include_names: bool = True) -> List[str]:
        """Get function argument list from FormalArg facts."""
        args = []
        for fact in facts:
            if fact.name == "FormalArg" and fact.args[0] == func_name:
                idx = fact.args[1]
                if include_names:
                    args.append((idx, f"{fact.args[2]}: {fact.args[3]}"))
                else:
                    args.append((idx, fact.args[3]))
        args.sort(key=lambda x: x[0])
        return [a[1] for a in args]

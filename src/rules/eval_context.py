"""
Evaluation context for Hy rule predicates.

This provides a unified context object that Hy predicates can use to access
facts, source code, and project-wide information.
"""

from dataclasses import dataclass
from typing import Any, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from core.context import ProjectContext
    from core.facts import Fact


@dataclass
class EvalContext:
    """
    Context passed to Hy rule predicates.

    Provides access to:
    - Project context (global facts index, module index, etc.)
    - Current file being analyzed
    - Source code and parse tree for the current file

    Usage in Hy predicates:
        (defn my-prop? [f facts ctx]
          ;; Access global facts
          (setv global-facts (. ctx ctx global-facts-index))
          ;; Access current file
          (setv file (. ctx current-file))
          ...)
    """

    ctx: "ProjectContext"  # Full project context
    current_file: str  # Path to current source file
    current_source: Optional[str] = None  # Source code of current file
    current_root: Optional[Any] = None  # tree-sitter root node

    @property
    def global_facts_index(self):
        """Get the global facts index from project context."""
        return self.ctx.global_facts_index

    @property
    def module_index(self):
        """Get the module index from project context."""
        return self.ctx.module_index

    def get_file_facts(self, file_path: str) -> List["Fact"]:
        """Get facts for a specific file."""
        file_ctx = self.ctx.source_files.get(file_path)
        if file_ctx:
            return file_ctx.facts
        return []

    def get_function_facts(self, func_name: str) -> List["Fact"]:
        """Get all facts for a function from the global index."""
        if func_name not in self.ctx.global_facts_index:
            return []

        all_facts = []
        for file_path, facts_list in self.ctx.global_facts_index[func_name].items():
            all_facts.extend(facts_list)
        return all_facts

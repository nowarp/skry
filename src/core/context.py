"""
Describes the global mutable context used to keep all the semantic and structural information about the project under analysis.
"""

from typing import List, Dict, Any, Optional, TYPE_CHECKING
from dataclasses import dataclass, field

from move.utils import SourceLocation
from core.facts import Fact
from move.ir import Function

if TYPE_CHECKING:
    from taint.interproc import FunctionSummary
    from analysis.function_index import FunctionIndex
    from analysis.call_graph import CallGraph

# Type alias for the global facts index
# Maps: fully_qualified_function_name -> file_path -> list of facts
# This allows handling duplicate function definitions across files
GlobalFactsIndex = Dict[str, Dict[str, List[Fact]]]

# Type alias for the module index
# Maps: fully_qualified_function_name -> Function IR
ModuleIndex = Dict[str, Function]


@dataclass
class SourceFileContext:
    path: str
    root: Optional[Any] = None
    source_code: Optional[str] = None
    source_code_hash: Optional[str] = None
    facts: List[Fact] = field(default_factory=list)
    is_test_only: bool = False  # True if module has #[test_only] annotation
    # Import resolution: alias -> fully qualified path (e.g., "ManagerCap" -> "typus_nft::typus_nft::ManagerCap")
    import_map: Dict[str, str] = field(default_factory=dict)
    # Fully qualified module path (e.g., "typus_nft::discount_mint")
    module_path: Optional[str] = None


class ProjectContext:
    """
    Describes the whole project-under-analysis context keeping all the information
    required for cross-module and cross-file analysis.
    """

    def __init__(self, source_files: List[str]):
        self.source_files: Dict[str, SourceFileContext] = {path: SourceFileContext(path) for path in source_files}
        self.global_facts_index: GlobalFactsIndex = {}
        self.all_location_maps: Dict[str, Dict[str, SourceLocation]] = {}
        self.module_index: ModuleIndex = {}  # func_name -> Function IR
        self.project_facts: List[Fact] = []  # Project-level facts (FeatureVersion, IsVersion, etc.)
        self.function_summaries: Dict[str, "FunctionSummary"] = {}  # IPA summaries for cross-module taint
        self._function_index: Optional["FunctionIndex"] = None  # Lazy-built function metadata index
        self.call_graph: Optional["CallGraph"] = None  # Pre-computed call graph IR
        self.semantic_facts: List[Fact] = []  # LLM-derived semantic facts (IsUserAsset, etc.)
        self.sensitivity_facts: List[Fact] = []  # Field sensitivity analysis facts

    @property
    def function_index(self) -> "FunctionIndex":
        """Get function metadata index (built lazily on first access)."""
        if self._function_index is None:
            from analysis.function_index import FunctionIndex

            self._function_index = FunctionIndex(self)
        return self._function_index

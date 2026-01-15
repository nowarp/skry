"""
Function metadata index for efficient lookups.

Builds an index of function visibility and access control facts once,
enabling O(1) lookups instead of iterating all source files per query.
"""

from dataclasses import dataclass
from typing import Dict, List, Tuple, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from core.context import ProjectContext


@dataclass
class FunctionMeta:
    """Metadata about a function."""

    is_init: bool = False
    is_public: bool = False
    is_entry: bool = False
    is_friend: bool = False
    checks_sender: bool = False

    @property
    def visibility_priority(self) -> int:
        """
        Get visibility priority for sorting (lower = higher priority).

        Priority order:
        0: init
        1: public entry
        2: entry (without public)
        3: public
        4: public(package) / friend
        5: private
        """
        if self.is_init:
            return 0
        elif self.is_public and self.is_entry:
            return 1
        elif self.is_entry:
            return 2
        elif self.is_public:
            return 3
        elif self.is_friend:
            return 4
        else:
            return 5

    @property
    def is_public_entry(self) -> bool:
        """Check if function is both public and entry."""
        return self.is_public and self.is_entry

    @property
    def ac_flags(self) -> List[str]:
        """Get access control flags for display (e.g., ['init', 'checks sender'])."""
        flags = []
        if self.is_init:
            flags.append("init")
        if self.checks_sender:
            flags.append("checks sender")
        return flags


class FunctionIndex:
    """
    Index of function metadata for efficient lookups.

    Build once per context, then use for O(1) lookups.
    """

    def __init__(self, ctx: "ProjectContext"):
        """Build index from project context."""
        self._index: Dict[str, FunctionMeta] = {}
        self._build_index(ctx)

    def _build_index(self, ctx: "ProjectContext") -> None:
        """Build function metadata index from facts."""
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "Fun":
                    func_name = fact.args[0]
                    if func_name not in self._index:
                        self._index[func_name] = FunctionMeta()

                elif fact.name == "IsInit":
                    func_name = fact.args[0]
                    if func_name not in self._index:
                        self._index[func_name] = FunctionMeta()
                    self._index[func_name].is_init = True

                elif fact.name == "IsPublic":
                    func_name = fact.args[0]
                    if func_name not in self._index:
                        self._index[func_name] = FunctionMeta()
                    self._index[func_name].is_public = True

                elif fact.name == "IsEntry":
                    func_name = fact.args[0]
                    if func_name not in self._index:
                        self._index[func_name] = FunctionMeta()
                    self._index[func_name].is_entry = True

                elif fact.name == "IsFriend":
                    func_name = fact.args[0]
                    if func_name not in self._index:
                        self._index[func_name] = FunctionMeta()
                    self._index[func_name].is_friend = True

                elif fact.name == "HasSenderEqualityCheck":
                    func_name = fact.args[0]
                    if func_name not in self._index:
                        self._index[func_name] = FunctionMeta()
                    self._index[func_name].checks_sender = True

    def get(self, func_name: str) -> FunctionMeta:
        """Get function metadata (returns default if not found)."""
        return self._index.get(func_name, FunctionMeta())

    def get_sort_key(self, func_name: str) -> Tuple[int, str]:
        """Get sort key for function ordering (priority, name)."""
        meta = self.get(func_name)
        return (meta.visibility_priority, func_name)

    def get_ac_flags(self, func_name: str) -> List[str]:
        """Get access control flags for function."""
        return self.get(func_name).ac_flags

    def is_private(self, func_name: str) -> bool:
        """Check if function is private (visibility priority 5)."""
        return self.get(func_name).visibility_priority == 5

    def functions(self) -> Set[str]:
        """Get all indexed function names."""
        return set(self._index.keys())

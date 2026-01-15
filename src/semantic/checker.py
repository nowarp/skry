"""
Semantic property checker module.

Provides SemanticChecker class used by hy_bridge to access project context.
The actual check implementations are in separate modules and called directly.
"""

from core.context import ProjectContext


class SemanticChecker:
    """
    Context holder for semantic property checks.

    The check functions (in taint_checks.py, access_checks.py, etc.) receive
    a SemanticChecker instance to access the project context and source file info.
    """

    def __init__(self, ctx: ProjectContext, source_file: str):
        self.ctx = ctx
        self.source_file = source_file

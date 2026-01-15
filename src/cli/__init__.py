"""
CLI utilities: environment validation, file collection, debug commands.
"""

from cli.helpers import (
    validate_environment,
    collect_source_files,
    collect_rule_files,
    parse_hy_rules,
    parse_all_rules,
    AnyRule,
)
from cli.debug import (
    dump_ast_tree,
    dump_ast_impl,
    check_parser_impl,
    dump_fact_schemas,
)

__all__ = [
    "validate_environment",
    "collect_source_files",
    "collect_rule_files",
    "parse_hy_rules",
    "parse_all_rules",
    "AnyRule",
    "dump_ast_tree",
    "dump_ast_impl",
    "check_parser_impl",
    "dump_fact_schemas",
]

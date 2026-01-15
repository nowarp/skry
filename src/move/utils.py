"""
Shared utilities for Move parsing.
"""

import bisect
from typing import List, Tuple, Dict
from dataclasses import dataclass

# Cache for line offset tables: id(source_code) -> list of byte offsets
_line_offset_cache: Dict[int, List[int]] = {}

# Limit for comment extraction to prevent prompt bloat
MAX_COMMENT_LENGTH = 300

# Cache for source bytes: id(source_code) -> (hash, bytes)
_source_bytes_cache: Dict[int, Tuple[int, bytes]] = {}


def _get_source_bytes(source_code: str) -> bytes:
    """Get cached bytes for source code (for tree-sitter byte offset extraction)."""
    cache_key = id(source_code)
    content_hash = hash(source_code)
    cached = _source_bytes_cache.get(cache_key)
    if cached is not None and cached[0] == content_hash:
        return cached[1]
    encoded = source_code.encode("utf-8")
    _source_bytes_cache[cache_key] = (content_hash, encoded)
    return encoded


def _extract_text(source_code: str, start_byte: int, end_byte: int) -> str:
    """
    Extract text from source using tree-sitter byte offsets.

    Tree-sitter returns byte offsets, but Python strings use character offsets.
    For ASCII-only files these are the same, but for files with non-ASCII chars
    (like →, Chinese, emoji, etc.) we need to use the byte representation.
    """
    source_bytes = _get_source_bytes(source_code)
    return source_bytes[start_byte:end_byte].decode("utf-8", errors="replace")


@dataclass
class SourceLocation:
    """Source code location: file, line, column (1-indexed for display)."""

    file: str
    line: int
    column: int

    def __str__(self) -> str:
        return f"{self.file}:{self.line}:{self.column}"


def _build_line_offset_table(source_code: str) -> List[int]:
    """Build table of byte offsets where each line starts. O(n) once per file."""
    offsets = [0]  # Line 1 starts at byte 0
    for i, c in enumerate(source_code):
        if c == "\n":
            offsets.append(i + 1)
    return offsets


def _byte_to_line_col(source_code: str, byte_pos: int) -> Tuple[int, int]:
    """
    Convert byte position to (line, column) tuple (1-indexed).
    Uses cached lookup table + binary search for O(log n) per call.
    """
    if byte_pos < 0:
        return (1, 1)
    if byte_pos >= len(source_code):
        byte_pos = len(source_code) - 1 if source_code else 0

    cache_key = id(source_code)
    if cache_key not in _line_offset_cache:
        _line_offset_cache[cache_key] = _build_line_offset_table(source_code)

    line_offsets = _line_offset_cache[cache_key]
    line = bisect.bisect_right(line_offsets, byte_pos)
    col = byte_pos - line_offsets[line - 1] + 1

    return (line, col)


def _extract_preceding_comment(node, source_code: str) -> str | None:
    """Extract comment(s) immediately preceding a node.

    Truncates to MAX_COMMENT_LENGTH to prevent LLM prompt bloat.
    """
    comments = []
    prev = node.prev_sibling

    while prev is not None:
        if prev.type == "line_comment":
            comment_text = _extract_text(source_code, prev.start_byte, prev.end_byte)
            comment_text = comment_text.lstrip("/").strip()
            comments.insert(0, comment_text)
            prev = prev.prev_sibling
        elif prev.type == "block_comment":
            comment_text = _extract_text(source_code, prev.start_byte, prev.end_byte)
            comment_text = comment_text.strip("/*").strip("*/").strip()
            comments.insert(0, comment_text)
            prev = prev.prev_sibling
        elif prev.type == "newline":
            prev = prev.prev_sibling
        else:
            break

    if not comments:
        return None

    result = "\n".join(comments)
    if len(result) > MAX_COMMENT_LENGTH:
        result = result[:MAX_COMMENT_LENGTH] + "..."
    return result

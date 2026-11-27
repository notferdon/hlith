# SPDX-License-Identifier: Apache-2.0
"""Source slicing that follows Python AST physical line numbering."""

from __future__ import annotations

import ast
import re

_AST_LINE_BREAKS = re.compile(r"(?<=\n)|(?<=\r)(?!\n)")


def ast_source_lines(source: str) -> list[str]:
    """Split only on LF, CRLF, or CR, the line endings counted by the parser."""
    return _AST_LINE_BREAKS.split(source)


def source_segment_from_lines(source_line_bytes: list[bytes], node: ast.AST) -> str | None:
    line_number = getattr(node, "lineno", None)
    end_line_number = getattr(node, "end_lineno", None)
    start_column = getattr(node, "col_offset", None)
    end_column = getattr(node, "end_col_offset", None)
    if (
        line_number is None
        or end_line_number is None
        or start_column is None
        or end_column is None
        or line_number < 1
        or end_line_number > len(source_line_bytes)
    ):
        return None
    first = source_line_bytes[line_number - 1][start_column:]
    last = source_line_bytes[end_line_number - 1][:end_column]
    if line_number == end_line_number:
        return source_line_bytes[line_number - 1][start_column:end_column].decode("utf-8")
    middle = source_line_bytes[line_number:end_line_number - 1]
    return b"".join([first, *middle, last]).decode("utf-8")


def ast_source_segment(source: str, node: ast.AST) -> str | None:
    """Return a source span using AST UTF-8 byte columns and parser line numbers."""
    lines = [line.encode("utf-8") for line in ast_source_lines(source)]
    return source_segment_from_lines(lines, node)

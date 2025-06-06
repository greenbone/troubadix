# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

"""Utilities for text processing and string manipulation in NASL files."""

import bisect


def handle_string_context(
    char: str, escape_next: bool, in_double_quote: bool, in_single_quote: bool
) -> tuple[bool, bool, bool]:
    """
    Helper function to track string contexts and escape sequences while parsing.

    Args:
        char: The current character being processed
        escape_next: Whether the next character should be escaped
        in_double_quote: Whether currently in a double-quoted string
        in_single_quote: Whether currently in a single-quoted string

    Returns:
        A tuple containing the updated (escape_next, in_double_quote, in_single_quote) values
    """
    # Handle escaped character
    if escape_next:
        return False, in_double_quote, in_single_quote
    # Set escape flag if backslash is encountered in a single quote string
    elif char == "\\" and in_single_quote:
        return True, in_double_quote, in_single_quote
    # Track string contexts, handling escaped quotes
    elif char == '"' and not in_single_quote:
        return False, not in_double_quote, in_single_quote
    elif char == "'" and not in_double_quote:
        return False, in_double_quote, not in_single_quote

    # No change to the state
    return escape_next, in_double_quote, in_single_quote


def build_line_starts(text: str) -> list[int]:
    """
    Precomputes starting indices for all lines in the text
    Returns: List of starting indices (first line starts at 0)
    """
    starts = [0]
    for i, char in enumerate(text):
        if char == "\n":
            starts.append(i + 1)  # Next line starts after newline
    return starts


def index_to_linecol(
    text: str, index: int, line_starts: list[int] = None
) -> tuple[int, int]:
    """
    Converts character index to (line_number, column_number) (1-indexed)

    Args:
        text: Input string
        index: Character position to locate
        line_starts: Precomputed line starts (optional)
    Returns:
        (line, column) tuple (both start at 1)
    """
    if line_starts is None:
        line_starts = build_line_starts(text)

    # Find last line start <= index
    line_num = bisect.bisect_right(line_starts, index)
    line_start = line_starts[line_num - 1]
    column = index - line_start + 1
    return (line_num, column)


def is_position_in_string(text: str, position: int) -> bool:
    """Check if the given position is inside a string literal."""
    in_double_quote = False
    in_single_quote = False
    escape_next = False

    # Process characters up to (but not including) the position
    # to determine the string state at that position
    for i in range(position):
        char = text[i]
        escape_next, in_double_quote, in_single_quote = handle_string_context(
            char, escape_next, in_double_quote, in_single_quote
        )
    return in_double_quote or in_single_quote

# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

"""Utilities for text processing and string manipulation in NASL files."""


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


def index_to_linecol(text: str, index: int) -> tuple[int, int]:
    """
    Converts character index to (line_number, column_number) (1-indexed)

    Args:
        text: Input string
        index: Character position to locate
    Returns:
        (line, column) tuple (both start at 1)
    """
    if index < 0 or index > len(text):
        raise ValueError(
            f"Index {index} out of bounds for text of length {len(text)}"
        )

    line = 1
    column = 1

    for i in range(index):
        if text[i] == "\n":
            line += 1
            column = 1
        else:
            column += 1

    return (line, column)


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

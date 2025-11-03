# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

"""Utilities for text processing and string manipulation in NASL files."""


class StringState:
    """
    A class to track string contexts and escape sequences while parsing text.
    """

    def __init__(
        self,
        escape_next: bool = False,
        in_double_quote: bool = False,
        in_single_quote: bool = False,
    ):
        self.escape_next = escape_next
        self.in_double_quote = in_double_quote
        self.in_single_quote = in_single_quote

    @property
    def in_string(self) -> bool:
        """Check if currently inside a string literal."""
        return self.in_double_quote or self.in_single_quote

    def process_next_char(self, char: str) -> None:
        """
        Process the next character and update the string state accordingly.

        Args:
            char: The current character being processed
        """
        # Handle escaped character
        if self.escape_next:
            self.escape_next = False
        # Set escape flag if backslash is encountered in a single quote string
        elif char == "\\" and self.in_single_quote:
            self.escape_next = True
        # Switch quote states
        elif char == '"' and not self.in_single_quote:
            self.in_double_quote = not self.in_double_quote
        elif char == "'" and not self.in_double_quote:
            self.in_single_quote = not self.in_single_quote


def index_to_linecol(text: str, index: int) -> tuple[int, int]:
    """
    Converts character index to (line_number, column_number) (1-based index)

    Args:
        text: Input string
        index: Character position to locate
    Returns:
        (line, column) tuple (both start at 1)
    """
    if index < 0 or index >= len(text):
        raise ValueError(
            f"Index {index} out of bounds for text of length {len(text)}"
        )

    lines = text.splitlines(keepends=True)
    line_num = 0
    for line_num, line in enumerate(lines, 1):
        if index < len(line):
            break
        index -= len(line)
    return (line_num, index + 1)


def is_position_in_string(text: str, position: int) -> bool:
    """Check if the given position is inside a string literal."""
    string_state = StringState()

    # Process characters up to (but not including) the position
    # to determine the string state at that position
    for char in text[:position]:
        string_state.process_next_char(char)

    return string_state.in_string


def find_matching_brace(
    text: str, opening_pos: int, braces: tuple[str, str] = ("(", ")")
) -> int | None:
    """
    Return the index of the matching closing brace for the brace at opening_pos.
    """
    opening, closing = braces
    depth = 1
    string_state = StringState()

    for pos in range(opening_pos + 1, len(text)):
        char = text[pos]
        string_state.process_next_char(char)

        if string_state.in_string:
            continue

        if char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return pos
    return None

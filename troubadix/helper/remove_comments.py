# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

from troubadix.helper.text_utils import StringState


def remove_comments(file_content: str) -> str:
    """
    Remove all commented portions from file content while preserving string literals.
    This function:
    1. Removes content from lines that start with '#' (also after whitespace)
    2. For lines with inline comments, keeps only the content before the '#'
    3. Preserves '#' characters within string literals
    4. Maintains original line numbers by keeping empty lines
    5. Handles multiline strings
    Args:
        file_content: String containing the full file content
    Returns:
        String with comments removed
    """
    string_state = StringState()
    return "\n".join(
        [
            _remove_comments_in_line(line, string_state)
            for line in file_content.splitlines()
        ]
    )


def _remove_comments_in_line(line: str, state: StringState) -> str:
    if not state.in_string and line.lstrip().startswith("#"):
        return ""

    for i, char in enumerate(line):
        state.process_next_char(char)
        if char == "#" and not state.in_string:
            return line[:i]

    return line

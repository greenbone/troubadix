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
    lines = file_content.splitlines()
    clean_lines = []

    string_state = StringState()

    for line in lines:
        # Skip lines that are entirely comments (after whitespace) if not in a string
        if not string_state.in_string and line.lstrip().startswith("#"):
            clean_lines.append("")  # Keep empty line to maintain line numbers
            continue

        # Handle inline comments (but respect strings)
        processed_line = ""

        for char in line:
            string_state.process_next_char(char)
            # Check for comment outside of strings
            if char == "#" and not string_state.in_string:
                break

            processed_line += char

        clean_lines.append(processed_line)

    return "\n".join(clean_lines)

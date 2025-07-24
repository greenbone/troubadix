# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

import re
from pathlib import Path
from typing import Iterator

from troubadix.helper.if_block_parser import find_if_statements
from troubadix.helper.remove_comments import remove_comments
from troubadix.helper.text_utils import index_to_linecol, is_position_in_string
from troubadix.plugin import (
    FileContentPlugin,
    LinterError,
    LinterResult,
    LinterWarning,
)

# minimal regex to match display() calls, content inside parentheses does not matter
DISPLAY_PATTERN = re.compile(r"display\s*\(.*;")
# matches any condition that contains "debug" such as ssh_debug, DEBUG, etc.
DEBUG_PATTERN = re.compile(r"debug", re.IGNORECASE)
EXCLUDED_FILES = {
    "global_settings.inc",
    "bin.inc",
    "dump.inc",
}


class CheckUsingDisplay(FileContentPlugin):
    name = "check_using_display"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        if nasl_file.name in EXCLUDED_FILES:
            return

        comment_free_content = remove_comments(file_content)

        display_matches = list(DISPLAY_PATTERN.finditer(comment_free_content))

        if not display_matches:
            return

        if_statements = find_if_statements(comment_free_content).statements

        for display_match in display_matches:
            display_pos = display_match.start()

            # Skip if this match is inside a string literal
            if is_position_in_string(comment_free_content, display_pos):
                continue

            # Check if this display is inside any if statement
            containing_if = None
            for if_statement in if_statements:
                if if_statement.if_start < display_pos < if_statement.if_end:
                    # inner most if statement containing the display,
                    containing_if = if_statement
                    # break  # Uncomment this line to get the outermost if statement

            # Case 1: Not in any if statement - ERROR
            if not containing_if:
                line_start = (
                    comment_free_content.rfind("\n", 0, display_pos) + 1
                )
                line_end = comment_free_content.find("\n", display_pos)
                if line_end == -1:
                    line_end = len(comment_free_content)

                context = comment_free_content[line_start:line_end].strip()
                line, _ = index_to_linecol(comment_free_content, display_pos)
                yield LinterError(
                    f"VT is using a display() without any if statement at line {line}: {context}",
                    file=nasl_file,
                    plugin=self.name,
                )
                continue

            # Case 2: Check if it's inside a debug if - OKAY
            in_debug_if = False
            for debug_if in if_statements:
                if (
                    DEBUG_PATTERN.search(debug_if.condition)
                    and debug_if.if_start < display_pos < debug_if.if_end
                ):
                    in_debug_if = True
                    break

            # Case 3: In an if but not in a debug if - WARNING
            if not in_debug_if:
                line, _ = index_to_linecol(comment_free_content, display_pos)
                yield LinterWarning(
                    "VT is using a display() inside an if statement"
                    f" but without debug check at line {line}\n"
                    + comment_free_content[
                        containing_if.if_start : containing_if.if_end
                    ],
                    file=nasl_file,
                    plugin=self.name,
                )

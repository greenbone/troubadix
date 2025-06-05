# Copyright (C) 2025 Greenbone AG
# SPDX-License-Identifier: GPL-3.0-or-later

import re
from pathlib import Path
from typing import Iterator

from troubadix.helper.if_block_parser import find_if_statements
from troubadix.helper.remove_comments import remove_comments
from troubadix.helper.text_utils import is_position_in_string
from troubadix.plugin import (
    FileContentPlugin,
    LinterError,
    LinterResult,
    LinterWarning,
)

DISPLAY_PATTERN = re.compile(r"display\s*\(.*;")
# matches any condition that contains "debug" such as ssh_debug, DEBUG, etc.
DEBUG_PATTERN = re.compile(r"debug", re.IGNORECASE)
EXLUDED_FILES = {
    "global_settings.inc",
    "bin.inc",
    "dump.inc",
}


class CheckUsingDisplayNew(FileContentPlugin):
    name = "check_using_display_new"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        if nasl_file.name in EXLUDED_FILES:
            return

        comment_free_content = remove_comments(file_content)
        try:
            if_statements = find_if_statements(comment_free_content)
        except ValueError as e:
            yield LinterError(
                str(e),
                file=nasl_file,
                plugin=self.name,
            )
            return

        # Find all display() calls in the entire file
        all_display_matches = list(
            DISPLAY_PATTERN.finditer(comment_free_content)
        )

        for display_match in all_display_matches:
            display_pos = display_match.start()

            # Skip if this match is inside a string literal
            if is_position_in_string(comment_free_content, display_pos):
                continue

            # Check if this display is inside any if statement
            containing_if = None
            for if_statement in if_statements:
                if (
                    if_statement.position[0]
                    < display_pos
                    < if_statement.position[1]
                ):
                    # inner most if statement containing the display,
                    # adding break after finding the first match results in the outermost if
                    containing_if = if_statement

            # Case 1: Not in any if statement - ERROR
            if not containing_if:
                line_start = (
                    comment_free_content.rfind("\n", 0, display_pos) + 1
                )
                line_end = comment_free_content.find("\n", display_pos)
                if line_end == -1:
                    line_end = len(comment_free_content)

                context = comment_free_content[line_start:line_end].strip()
                yield LinterError(
                    f"VT is using a display() without any if statement: {context}",
                    file=nasl_file,
                    plugin=self.name,
                )
                continue

            # Case 2: Check if it's inside a debug if - OKAY
            in_debug_if = False
            for debug_if in if_statements:
                if (
                    DEBUG_PATTERN.search(debug_if.condition)
                    and debug_if.position[0]
                    < display_pos
                    < debug_if.position[1]
                ):
                    in_debug_if = True
                    break

            # Case 3: In an if but not in a debug if - WARNING
            if not in_debug_if:
                yield LinterWarning(
                    "VT is using a display() inside an if statement but without debug check\n"
                    + comment_free_content[
                        containing_if.position[0] : containing_if.position[1]
                    ],
                    file=nasl_file,
                    plugin=self.name,
                )

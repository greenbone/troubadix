# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

import re
from collections.abc import Iterator
from pathlib import Path

from troubadix.plugin import FileContentPlugin, LinterError, LinterResult

r"""
Matches full script_add_preference calls.
Consumes the literal name and optional whitespace before '('.
Captures the payload in group "value" as repeated non-quote text
(`[^"()]*`) or quoted strings.
The quoted branch (`"[^"\\]*(?:\\.[^"\\]*)*"`) starts with `"`, reads
non-quote or escaped characters, and ends on an unescaped `"`.
These fragments repeat so inner parentheses and `);` stay inside the
capture until the real closing `)` appears.
The suffix `\)\s*;` enforces the closing parenthesis and semicolon, and
DOTALL lets the match span newlines.
"""
ADD_PREFERENCE_PATTERN = re.compile(
    r"script_add_preference\s*\((?P<value>(?:[^\"()]*|\"[^\"\\]*(?:\\.[^\"\\]*)*\")*)\)\s*;",
    re.DOTALL,
)
ID_PATTERN = re.compile(r"id\s*:\s*(?P<id>\d+)")


class CheckScriptAddPreferenceId(FileContentPlugin):
    name = "check_script_add_preference_id"

    def check_content(
        self, nasl_file: Path, file_content: str
    ) -> Iterator[LinterResult]:
        """
        Checks for duplicate IDs in script_add_preference calls.
        """
        if (
            nasl_file.suffix == ".inc"
            or "script_add_preference" not in file_content
        ):
            return

        # Primary regex to capture all script_add_preference calls
        preferences_matches = ADD_PREFERENCE_PATTERN.finditer(file_content)

        seen_ids: set[int] = set()

        # Secondary id regex
        for index, pref_match in enumerate(preferences_matches, 1):
            id_match = ID_PATTERN.search(pref_match.group("value"))
            # If no ID is provided, the preference ID defaults to the entry's position at runtime
            pref_id = int(id_match.group("id")) if id_match else index

            if pref_id in seen_ids:
                yield LinterError(
                    f"script_add_preference id {pref_id} is used multiple times",
                    file=nasl_file,
                    plugin=self.name,
                )

            seen_ids.add(pref_id)

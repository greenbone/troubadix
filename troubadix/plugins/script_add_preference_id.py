# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

import re
from collections.abc import Iterator
from pathlib import Path

from troubadix.helper.patterns import (
    SpecialScriptTag,
    get_special_script_tag_pattern,
)
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult

ID_PATTERN = re.compile(r"id\s*:\s*(?P<id>\d+)")


class CheckScriptAddPreferenceId(FileContentPlugin):
    name = "check_script_add_preference_id"

    def check_content(
        self, nasl_file: Path, file_content: str
    ) -> Iterator[LinterResult]:
        """
        checks for duplicate ids in script_add_preference calls
        """
        if (
            nasl_file.suffix == ".inc"
            or "script_add_preference" not in file_content
        ):
            return

        # Primary regex to capture all script_add_preference calls
        preferences_matches = get_special_script_tag_pattern(
            SpecialScriptTag.ADD_PREFERENCE
        ).finditer(file_content)

        seen = set()

        # Secondary id regex
        for pref_match in preferences_matches:
            id_match = ID_PATTERN.search(pref_match.group("value"))
            # id is optional so just continue if secondary regex does not match
            if not id_match:
                continue

            pref_id = id_match.group("id")
            if pref_id in seen:

                yield LinterError(
                    f"script_add_preference id {pref_id} is used multiple times",
                    file=nasl_file,
                    plugin=self.name,
                )
            seen.add(pref_id)

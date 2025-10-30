# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

import re
from collections.abc import Iterator
from pathlib import Path

from troubadix.helper.text_utils import find_matching_brace
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult

SCRIPT_CALL_PATTERN = re.compile(r"script_add_preference\s*\(")
ID_PATTERN = re.compile(r"id\s*:\s*(?P<id>\d+)")


def iter_script_add_preference_values(
    source: str,
) -> Iterator[str]:
    for match in SCRIPT_CALL_PATTERN.finditer(source):
        opening_paren = match.end() - 1
        closing_paren = find_matching_brace(source, opening_paren, ("(", ")"))
        if closing_paren is None:
            continue
        yield source[opening_paren + 1 : closing_paren]


class CheckScriptAddPreferenceId(FileContentPlugin):
    name = "check_script_add_preference_id"

    def check_content(
        self, nasl_file: Path, file_content: str
    ) -> Iterator[LinterResult]:
        if (
            nasl_file.suffix == ".inc"
            or "script_add_preference" not in file_content
        ):
            return

        seen_ids: set[int] = set()

        for index, value in enumerate(
            iter_script_add_preference_values(file_content), 1
        ):
            id_match = ID_PATTERN.search(value)
            pref_id = int(id_match.group("id")) if id_match else index

            if pref_id in seen_ids:
                yield LinterError(
                    f"script_add_preference id {pref_id} is used multiple times",
                    file=nasl_file,
                    plugin=self.name,
                )

            seen_ids.add(pref_id)

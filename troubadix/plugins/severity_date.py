# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

from pathlib import Path
from typing import Iterator

from troubadix.helper import ScriptTag, get_script_tag_pattern
from troubadix.helper.date_format import (
    check_date,
    compare_date_with_last_modification_date,
)
from troubadix.plugin import FileContentPlugin, LinterResult


class CheckSeverityDate(FileContentPlugin):
    name = "check_severity_date"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:

        if nasl_file.suffix == ".inc":
            return

        severity_date_pattern = get_script_tag_pattern(ScriptTag.SEVERITY_DATE)
        last_modification_pattern = get_script_tag_pattern(
            ScriptTag.LAST_MODIFICATION
        )

        if not (
            match_severity_date := severity_date_pattern.search(file_content)
        ):
            return

        yield from check_date(
            match_severity_date.group("value"),
            "severity_date",
            nasl_file,
            self.name,
        )

        if match_last_mod_date := last_modification_pattern.search(
            file_content
        ):
            yield from compare_date_with_last_modification_date(
                match_severity_date.group("value"),
                "severity_date",
                match_last_mod_date.group("value"),
                nasl_file,
                self.name,
            )

# Copyright (C) 2025 Greenbone AG
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import datetime
from pathlib import Path
from typing import Iterator

from troubadix.helper import ScriptTag, get_script_tag_pattern
from troubadix.helper.date_format import check_date
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class CheckSeverityDate(FileContentPlugin):
    name = "check_severity_date"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        if (
            nasl_file.suffix == ".inc"
            or "# troubadix: disable=template_nd_test_files_fps" in file_content
        ):
            return

        severity_date_pattern = get_script_tag_pattern(ScriptTag.SEVERITY_DATE)
        last_modification_pattern = get_script_tag_pattern(
            ScriptTag.LAST_MODIFICATION
        )

        # Check severity date if available
        if match_severity_date := severity_date_pattern.search(file_content):
            yield from check_date(
                match_severity_date.group("value"),
                "severity_date",
                nasl_file,
                self.name,
            )
        else:
            return

        # Check last modification date if available
        if match_last_mod_date := last_modification_pattern.search(
            file_content
        ):

            yield from check_date(
                match_last_mod_date.group("value"),
                "last_modification",
                nasl_file,
                self.name,
            )

            try:
                severity_date = datetime.strptime(
                    match_severity_date.group("value")[:25],
                    "%Y-%m-%d %H:%M:%S %z",
                )
                last_modification_date = datetime.strptime(
                    match_last_mod_date.group("value")[:25],
                    "%Y-%m-%d %H:%M:%S %z",
                )
                if severity_date > last_modification_date:
                    yield LinterError(
                        "The severity date must not be greater than the "
                        "last modification date.",
                        file=nasl_file,
                        plugin=self.name,
                    )
            except Exception:
                pass

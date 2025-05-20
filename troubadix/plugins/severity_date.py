# Copyright (C) 2025 Greenbone AG
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import datetime
from pathlib import Path
from typing import Iterator

from troubadix.helper import ScriptTag, get_script_tag_pattern
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

        if "severity_date" not in file_content:
            return

        tag_pattern = get_script_tag_pattern(ScriptTag.SEVERITY_DATE)

        # Example: "2017-11-29 13:56:41 +0100 (Wed, 29 Nov 2017)"
        match = tag_pattern.search(file_content)

        if not match:
            yield LinterError(
                "False or incorrectly formatted severity_date.",
                file=nasl_file,
                plugin=self.name,
            )
            return

        try:
            date_left = datetime.strptime(
                match.group("value")[:25], "%Y-%m-%d %H:%M:%S %z"
            )
            # 2017-11-29 13:56:41 +0100 (error if no timezone)
            date_right = datetime.strptime(
                match.group("value")[27:43], "%a, %d %b %Y"
            )
            week_day_parsed = date_right.strftime("%a")
        except ValueError:
            yield LinterError(
                "False or incorrectly formatted severity_date.",
                file=nasl_file,
                plugin=self.name,
            )
            return

        week_day_str = match.group("value")[27:30]
        # Wed, 29 Nov 2017
        if date_left.date() != date_right.date():
            yield LinterError(
                "The severity_date consists of two different dates.",
                file=nasl_file,
                plugin=self.name,
            )
        # Check correct weekday
        elif week_day_str != week_day_parsed:
            formatted_date = week_day_parsed
            yield LinterError(
                f"Wrong day of week. Please change it from '{week_day_str}"
                f"' to '{formatted_date}'.",
                file=nasl_file,
                plugin=self.name,
            )

        last_modification_pattern = get_script_tag_pattern(
            ScriptTag.LAST_MODIFICATION
        )
        if match := last_modification_pattern.search(file_content):
            last_modification = datetime.strptime(
                match.group("value")[:25], "%Y-%m-%d %H:%M:%S %z"
            )
            if date_left > last_modification:
                yield LinterError(
                    "The severity_date must not be greater than the last modification date.",
                    file=nasl_file,
                    plugin=self.name,
                )

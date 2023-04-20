# Copyright (C) 2022 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from datetime import datetime
from pathlib import Path
from typing import Iterator

from troubadix.helper.patterns import ScriptTag, get_script_tag_pattern
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult

LENGTH = 44


class CheckCreationDate(FileContentPlugin):
    name = "creation_date"

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

        if not "creation_date" in file_content:
            yield LinterError(
                "No creation date has been found.",
                file=nasl_file,
                plugin=self.name,
            )
            return

        tag_pattern = get_script_tag_pattern(ScriptTag.CREATION_DATE)

        # Example: "2017-11-29 13:56:41 +0100 (Wed, 29 Nov 2017)"
        match = tag_pattern.search(file_content)

        if match:
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
                    "False or incorrectly formatted creation_date.",
                    file=nasl_file,
                    plugin=self.name,
                )
                return

            week_day_str = match.group("value")[27:30]
            # Wed, 29 Nov 2017
            if date_left.date() != date_right.date():
                yield LinterError(
                    "The creation_date consists of two different dates.",
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
        else:
            yield LinterError(
                "False or incorrectly formatted creation_date.",
                file=nasl_file,
                plugin=self.name,
            )
            return

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

from pathlib import Path
from typing import Iterator

from troubadix.helper.date_format import (
    check_date,
    compare_date_with_last_modification_date,
)
from troubadix.helper.patterns import ScriptTag, get_script_tag_pattern
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


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

        creation_date_pattern = get_script_tag_pattern(ScriptTag.CREATION_DATE)
        last_modification_pattern = get_script_tag_pattern(
            ScriptTag.LAST_MODIFICATION
        )

        if not (
            match_creation_date := creation_date_pattern.search(file_content)
        ):
            yield LinterError(
                "No creation_date has been found.",
                file=nasl_file,
                plugin=self.name,
            )
            return

        yield from check_date(
            match_creation_date.group("value"),
            "creation_date",
            nasl_file,
            self.name,
        )

        if match_last_mod_date := last_modification_pattern.search(
            file_content
        ):
            yield from compare_date_with_last_modification_date(
                match_creation_date.group("value"),
                "creation_date",
                match_last_mod_date.group("value"),
                nasl_file,
                self.name,
            )

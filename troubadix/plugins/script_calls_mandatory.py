# Copyright (C) 2022 Greenbone Networks GmbH
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

from troubadix.helper.patterns import (
    SpecialScriptTag,
    get_special_script_tag_pattern,
)
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class CheckScriptCallsMandatory(FileContentPlugin):
    name = "check_script_calls_mandatory"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """
        This script checks for the existence of the following mandatory script
        calls:
        - script_name
        - script_version
        - script_category
        - script_family
        - script_copyright
        """
        if nasl_file.suffix == ".inc":
            return

        mandatory_calls = [
            SpecialScriptTag.NAME,
            SpecialScriptTag.VERSION,
            SpecialScriptTag.CATEGORY,
            SpecialScriptTag.FAMILY,
            SpecialScriptTag.COPYRIGHT,
        ]

        for call in mandatory_calls:
            # if not re.search(r"script_" + call, file_content):
            if not get_special_script_tag_pattern(call).search(file_content):
                yield LinterError(
                    "VT does not contain the following mandatory call: "
                    f"'script_{call}'",
                    file=nasl_file,
                    plugin=self.name,
                )

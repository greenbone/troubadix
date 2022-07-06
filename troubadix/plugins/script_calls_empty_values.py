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
    _get_special_script_tag_pattern,
    _get_tag_pattern,
    get_xref_pattern,
)
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult

# For the future
SPECIAL_SCRIPT_TAG_LIST = []


class CheckScriptCallsEmptyValues(FileContentPlugin):
    name = "check_script_calls_empty_values"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """
        Checks for empty 'value:""' in script calls. Excepted from this is
        script_add_preferences().
        """
        if nasl_file.suffix == ".inc":
            return

        matches = _get_tag_pattern(name=r".*", value=r"").finditer(file_content)
        for match in matches:
            yield LinterError(
                f"{match.group(0)} does not contain a value",
                file=nasl_file,
                plugin=self.name,
            )

        matches = get_xref_pattern(name=r".*", value=r"").finditer(file_content)
        for match in matches:
            yield LinterError(
                f"{match.group(0)} does not contain a value",
                file=nasl_file,
                plugin=self.name,
            )

        for call in SPECIAL_SCRIPT_TAG_LIST:
            matches = _get_special_script_tag_pattern(
                name=call.value, value=""
            ).finditer(file_content)
            for match in matches:
                yield LinterError(
                    f"{match.group(0)} does not contain a value",
                    file=nasl_file,
                    plugin=self.name,
                )

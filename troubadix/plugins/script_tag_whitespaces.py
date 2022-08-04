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

import re
from pathlib import Path
from typing import Iterator

from troubadix.helper.patterns import _get_tag_pattern
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class CheckScriptTagWhitespaces(FileContentPlugin):
    name = "check_script_tag_whitespaces"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """
        Checks a given file content if a script tag value contains a leading or
        trailing whitespace character
        """
        if nasl_file.suffix == ".inc":
            return

        matches = _get_tag_pattern(name=r".+?", flags=re.S).finditer(
            file_content
        )

        for match in matches:
            if re.match(r"^\s+.*", match.group("value")) or re.match(
                r".*\s+$", match.group("value"), flags=re.S
            ):
                yield LinterError(
                    f"{match.group(0)}: value contains a leading or"
                    " trailing whitespace character",
                    file=nasl_file,
                    plugin=self.name,
                )

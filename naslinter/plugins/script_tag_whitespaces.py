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
from typing import Iterator, OrderedDict
from naslinter.helper.patterns import get_tag_pattern
from naslinter.plugin import FileContentPlugin, LinterError, LinterResult


class CheckScriptTagWhitespaces(FileContentPlugin):
    name = "check_script_tag_whitespaces"

    @staticmethod
    def run(
        nasl_file: Path,
        file_content: str,
        *,
        tag_pattern: OrderedDict[str, re.Pattern],
        special_tag_pattern: OrderedDict[str, re.Pattern],
    ) -> Iterator[LinterResult]:
        """
        Checks a given file content if a script tag value contains a leading or
        trailing whitespace character
        """
        del tag_pattern, special_tag_pattern
        if nasl_file.suffix == ".inc":
            return

        matches = get_tag_pattern(name=r".*", flags=re.S).finditer(file_content)

        for match in matches:
            if re.match(r"\s+.*", match.group("value")) or re.match(
                r".*\s+", match.group("value")
            ):
                yield LinterError(
                    f"{match.group(0)}: value contains a leading or"
                    " trailing whitespace character"
                )
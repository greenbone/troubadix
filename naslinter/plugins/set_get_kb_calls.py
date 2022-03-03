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

from naslinter.plugin import LinterError, FileContentPlugin, LinterResult


class CheckSetGetKbCalls(FileContentPlugin):
    name = "check_set_get_kb_calls"

    @staticmethod
    def run(_: Path, file_content: str) -> Iterator[LinterResult]:
        """
        Checks set and get kb entry calls for correct parameter usage.
        """
        name_re = re.compile(r"name\s*:")
        value_re = re.compile(r"value\s*:")

        set_matches = re.finditer(
            r"(set|replace)_kb_item\s*\((.*)\)\s*;", file_content
        )
        for set_match in set_matches:
            if set_match and set_match.group(2):
                if not re.search(name_re, set_match.group(2)) or not re.search(
                    value_re, set_match.group(2)
                ):
                    yield LinterError(
                        f"{set_match.group(0)}: missing name or value parameter"
                    )

        get_matches = re.finditer(
            r"get_kb_(item|list)\s*\((.*)\)\s*;", file_content
        )
        for get_match in get_matches:
            if get_match and get_match.group(2):
                if re.search(name_re, get_match.group(2)) or re.search(
                    value_re, get_match.group(2)
                ):
                    yield LinterError(
                        f"{get_match.group(0)}: should not contain parameter"
                        " names"
                    )

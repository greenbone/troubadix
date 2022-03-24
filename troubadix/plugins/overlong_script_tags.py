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
from typing import Iterable, Iterator

from troubadix.helper import is_ignore_file

from ..plugin import LineContentPlugin, LinterError, LinterResult

# Arbitrary limit adopted from original step
VALUE_LIMIT = 1000

IGNORE_FILES = [
    "gb_nmap6_",
    "monstra_cms_mult_vuln",
    "gb_huawei-sa-",
    "lsc_options.nasl",
]


class CheckOverlongScriptTags(LineContentPlugin):
    """This steps checks if the script_tag summary, impact,
    affected, insight, vuldetect or solution of a given VT
    contains an overlong line within the value string.

    Background for this is that (e.g. auto generated LSCs)
    are created by parsing an advisory and the whole
    content is placed in such a tag which could be quite large.
    """

    name = "check_overlong_script_tags"

    @staticmethod
    def run(
        nasl_file: Path,
        lines: Iterable[str],
    ) -> Iterator[LinterResult]:
        if is_ignore_file(nasl_file, IGNORE_FILES):
            return

        line_number = 1
        for line in lines:
            # Length of value to check is found in group 3
            # Tag name is found in group 2
            match = re.search(
                r"(script_tag\(\s*name\s*:\s*\""
                r"(summary|impact|affected|insight|vuldetect|solution)"
                r"\"\s*,\s*value\s*:\s*)\"([^\"]+)\"\)",
                line,
            )
            if match is not None:
                if len(match.group(3)) > VALUE_LIMIT:
                    yield LinterError(
                        f"line {line_number : 5}:"
                        f" contains overlong {match.group(2)}"
                        f" with {len(match.group(3))} characters"
                    )
            line_number += 1

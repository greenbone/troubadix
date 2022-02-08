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

from ..plugin import LinterError, FileContentPlugin, LinterResult


class CheckDoubleEndPoints(FileContentPlugin):
    name = "check_double_end_points"

    @staticmethod
    def run(nasl_file: Path, file_content: str) -> Iterator[LinterResult]:
        tag_matches = re.finditer(
            r'(script_tag\(name\s*:\s*"'
            r'(summary|impact|affected|insight|vuldetect|solution)"'
            r'\s*,\s*value\s*:\s*")([^"]+"\s*\)\s*;)',
            file_content,
            re.MULTILINE,
        )

        if tag_matches is not None:
            for tag_match in tag_matches:
                if tag_match is not None and tag_match.group(3) is not None:
                    doubled_end_points_match = re.search(
                        r'.*\.\s*\."\s*\)\s*;', tag_match.group(3), re.MULTILINE
                    )
                    if (
                        doubled_end_points_match is not None
                        and doubled_end_points_match.group(0) is not None
                    ):

                        # Valid string used in a few VTs.
                        if (
                            'and much more...");'
                            in doubled_end_points_match.group(0)
                        ):
                            continue

                        script_tag = tag_match.group(0).partition(",")[0]
                        yield LinterError(
                            f"The script tag '{script_tag}' of VT '{nasl_file}'"
                            f" is ending with two or more end points: "
                            f"'{doubled_end_points_match.group(0)}'."
                        )

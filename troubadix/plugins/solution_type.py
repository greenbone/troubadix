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

from troubadix.plugin import FileContentPlugin, LinterError, LinterResult

VALUES = (
    "Workaround",
    "Mitigation",
    "VendorFix",
    "NoneAvailable",
    "WillNotFix",
)


class CheckSolutionType(FileContentPlugin):
    """
    This script checks the passed VT for the existence/format of its
    solution_type with the help of regular expression.An error will be thrown
    if the VT does not contain a solution_type at all or of the solution_type
    contains an invalid value.
    """

    name = "check_solution_type"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:

        if nasl_file.suffix == ".inc":
            return

        has_severity = True
        cvss_detect = re.search(
            r"script_tag\s*\(name\s*:\s*\"cvss_base\","
            r"\s*value:\s*\"(\d{1,2}\.\d)\"\)",
            file_content,
        )
        if cvss_detect is not None and cvss_detect.group(1) == "0.0":
            has_severity = False

        match = re.search(
            r"script_tag\s*\(name\s*:\s*\"(solution_type)\"\s*,"
            r"\s*value\s*:\s*\"([a-zA-Z\s]+)\"\s*\)\s*;",
            file_content,
        )

        if has_severity:
            if match is None or match.group(1) is None:
                yield LinterError(
                    "VT does not contain a solution_type",
                    file=nasl_file,
                    plugin=self.name,
                )
        if match is not None and match.group(2) not in VALUES:
            yield LinterError(
                "VT does not contain a valid solution_type 'value'",
                file=nasl_file,
                plugin=self.name,
            )

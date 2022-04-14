# Copyright (C) 2021 Greenbone Networks GmbH
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
from typing import Iterable

from typing import Iterator

from troubadix.helper import is_ignore_file
from troubadix.plugin import LineContentPlugin, LinterError, LinterResult

_IGNORE_FILES = (
    "sw_telnet_os_detection.nasl",
    "gb_hp_comware_platform_detect_snmp.nasl",
    "gb_hirschmann_telnet_detect.nasl",
)


class CheckCopyrightYear(LineContentPlugin):
    """This steps checks if a VT contains a Copyright statement containing a
    year not matching the year defined in the creation_date statement like
    script_tag(name:"creation_date", value:"2017-
    """

    name = "check_copyright_year"

    def check_lines(
        self,
        nasl_file: Path,
        lines: Iterable[str],
    ) -> Iterator[LinterResult]:
        if nasl_file.suffix == ".inc":
            return

        report = ""
        copyright_date = ""
        copyright_year = ""
        copyright_dict = {}

        for line in lines:
            if "creation_date" in line:
                expre = re.search(r'value\s*:\s*"(.*)"', line)
                if expre is not None and expre.group(1) is not None:
                    copyright_date = expre.group(1)
                    expre = re.search(r"^([0-9]+)-", copyright_date)
                    if expre is not None and expre.group(1) is not None:
                        copyright_year = expre.group(1)

            copyright_match = re.search(
                r"(# |script_copyright.*)[Cc]opyright \([Cc]\) ([0-9]+)",
                line,
            )
            if (
                copyright_match is not None
                and copyright_match.group(2) is not None
                and not is_ignore_file(nasl_file, _IGNORE_FILES)
            ):
                copyright_dict[line] = copyright_match.group(2)

        if not copyright_year:
            yield LinterError("Missing creation_date statement in VT")

        # key is the line where the copyright is found, value the year found
        # within that line
        for key, value in copyright_dict.items():
            if value != copyright_year:
                report += f"\n{key.strip()}\n"

        if len(report) > 0:
            yield LinterError(
                "VT contains a Copyright year not matching "
                f"the year in {copyright_year} at the following lines:\n"
                f"{report}",
            )

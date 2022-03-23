#  Copyright (c) 2022 Greenbone Networks GmbH
#
#  SPDX-License-Identifier: GPL-3.0-or-later
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

from pathlib import Path
import re
from typing import Iterator, OrderedDict

from troubadix.helper import get_tag_pattern
from troubadix.helper.patterns import ScriptTag
from troubadix.plugin import LinterError, FileContentPlugin, LinterResult

VALID_QOD_NUM_VALUES = [
    1,
    30,
    50,
    70,
    75,
    80,
    95,
    97,
    98,
    99,
    100,
]

VALID_QOD_TYPES = [
    "exploit",
    "remote_vul",
    "remote_app",
    "package",
    "registry",
    "remote_active",
    "remote_banner",
    "executable_version",
    "remote_analysis",
    "remote_probe",
    "remote_banner_unreliable",
    "executable_version_unreliable",
    "general_note",
]


class CheckQod(FileContentPlugin):
    name = "check_qod"

    @staticmethod
    def run(
        nasl_file: Path,
        file_content: str,
        *,
        tag_pattern: OrderedDict[str, re.Pattern],
        special_tag_pattern: OrderedDict[str, re.Pattern],
    ) -> Iterator[LinterResult]:
        """
        The script checks the passed VT for the existence / validity of its QoD
        """
        del tag_pattern, special_tag_pattern

        match_qod = list(
            get_tag_pattern(name=ScriptTag.QOD, value=r".*").finditer(
                file_content
            )
        )
        match_qod_type = list(
            get_tag_pattern(name=ScriptTag.QOD_TYPE, value=r".*").finditer(
                file_content
            )
        )

        num_matches = len(match_qod) + len(match_qod_type)
        if num_matches < 1:
            yield LinterError("VT is missing QoD or QoD type")
        if num_matches > 1:
            yield LinterError("VT contains multiple QoD values")

        for match in match_qod:
            try:
                qod = int(match.group("value"))
                if qod not in VALID_QOD_NUM_VALUES:
                    yield LinterError(
                        f"{match.group(0)}: '{qod}' is an invalid QoD number"
                        " value. Allowed are"
                        f" {', '.join(str(x) for x in VALID_QOD_NUM_VALUES)}"
                    )
            except ValueError:
                yield LinterError(
                    f"{match.group(0)}: '{match.group('value')}' is an invalid"
                    " QoD number value. Allowed are"
                    f" {', '.join(str(x) for x in VALID_QOD_NUM_VALUES)}"
                )

        for match in match_qod_type:
            val = match.group("value").replace('"', "")
            if val not in VALID_QOD_TYPES:
                yield LinterError(
                    f"{match.group(0)}: '{match.group('value')}' is an invalid"
                    f" QoD type. Allowed are {', '.join(VALID_QOD_TYPES)}"
                )

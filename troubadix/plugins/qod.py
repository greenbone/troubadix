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

from typing import Iterator

from troubadix.helper.patterns import ScriptTag, get_script_tag_pattern
from troubadix.plugin import FilePlugin, LinterError, LinterResult

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


class CheckQod(FilePlugin):
    name = "check_qod"

    def run(self) -> Iterator[LinterResult]:
        """
        The script checks the passed VT for the existence / validity of its QoD
        """

        if self.context.nasl_file.suffix == ".inc":
            return

        file_content = self.context.file_content

        qod_pattern = get_script_tag_pattern(ScriptTag.QOD)
        qod_type_pattern = get_script_tag_pattern(ScriptTag.QOD_TYPE)

        match_qod = list(qod_pattern.finditer(file_content))
        match_qod_type = list(qod_type_pattern.finditer(file_content))

        num_matches = len(match_qod) + len(match_qod_type)
        if num_matches < 1:
            yield LinterError(
                "VT is missing QoD or QoD type",
                file=self.context.nasl_file,
                plugin=self.name,
            )
        if num_matches > 1:
            yield LinterError(
                "VT contains multiple QoD values",
                file=self.context.nasl_file,
                plugin=self.name,
            )

        for match in match_qod:
            try:
                qod = int(match.group("value"))
                if qod not in VALID_QOD_NUM_VALUES:
                    yield LinterError(
                        f"{match.group(0)}: '{qod}' is an invalid QoD number"
                        " value. Allowed are"
                        f" {', '.join(str(x) for x in VALID_QOD_NUM_VALUES)}",
                        file=self.context.nasl_file,
                        plugin=self.name,
                    )
            except ValueError:
                yield LinterError(
                    f"{match.group(0)}: '{match.group('value')}' is an invalid"
                    " QoD number value. Allowed are"
                    f" {', '.join(str(x) for x in VALID_QOD_NUM_VALUES)}",
                    file=self.context.nasl_file,
                    plugin=self.name,
                )

        for match in match_qod_type:
            val = match.group("value").replace('"', "")
            if val not in VALID_QOD_TYPES:
                yield LinterError(
                    f"{match.group(0)}: '{match.group('value')}' is an invalid"
                    f" QoD type. Allowed are {', '.join(VALID_QOD_TYPES)}",
                    file=self.context.nasl_file,
                    plugin=self.name,
                )

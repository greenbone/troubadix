#  Copyright (c) 2022 Greenbone AG
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

import re
from typing import Iterator

from troubadix.helper.patterns import ScriptTag, get_script_tag_pattern
from troubadix.plugin import FilePlugin, LinterError, LinterResult

VALID_QOD_NUM_VALUES = [
    "1",
    "30",
    "50",
    "70",
    "75",
    "80",
    "95",
    "97",
    "98",
    "99",
    "100",
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
    "package_unreliable",
]

# needed due to script_tag_pattern value not including the quotes
QOD_WITH_QUOTES_PATTERN = re.compile(
    r'script_tag\(\s*name\s*:\s*(?P<quote>[\'"])qod(?P=quote)\s*,'
    r'\s*value\s*:\s*(?P<value_with_quotes>[\'"]?(?P<value>.+?)[\'"]?)\s*\)\s*;'
)


class CheckQod(FilePlugin):
    name = "check_qod"

    def run(self) -> Iterator[LinterResult]:
        """
        The script checks the passed VT for the existence / validity of its QoD
        """

        if self.context.nasl_file.suffix == ".inc":
            return

        file_content = self.context.file_content

        if "# troubadix: disable=template_nd_test_files_fps" in file_content:
            return

        qod_type_pattern = get_script_tag_pattern(ScriptTag.QOD_TYPE)

        match_qod = list(QOD_WITH_QUOTES_PATTERN.finditer(file_content))
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
            full_match = match.group(0)
            full_value = match.group("value_with_quotes")
            value = match.group("value")

            # Check if the value is enclosed in double quotes
            if full_value.startswith('"') and full_value.endswith('"'):

                # Compare against valid values
                if value not in VALID_QOD_NUM_VALUES:
                    yield LinterError(
                        f"Invalid QOD value '{value}' in {full_match}."
                        " Allowed are"
                        f" {', '.join(x for x in VALID_QOD_NUM_VALUES)}",
                        file=self.context.nasl_file,
                        plugin=self.name,
                    )
            else:
                yield LinterError(
                    f"QOD value not properly enclosed in double quotes in {full_match}",
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

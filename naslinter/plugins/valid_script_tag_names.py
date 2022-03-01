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

from pathlib import Path
import re

from naslinter.plugin import LinterError, FileContentPlugin
from naslinter.helper import get_tag_pattern


class CheckValidScriptTagNames(FileContentPlugin):
    """This step checks if the name of the following script tag:

    - script_tag(name:"", value:"");

    is one of the following allowed ones:

    - script_tag(name:"solution", value:"");
    - script_tag(name:"qod_type", value:"");
    - script_tag(name:"cvss_base", value:"");
    - script_tag(name:"cvss_base_vector", value:"");
    - script_tag(name:"summary", value:"");
    - script_tag(name:"last_modification", value:"");
    - script_tag(name:"insight", value:"");
    - script_tag(name:"affected", value:"");
    - script_tag(name:"creation_date", value:"");
    - script_tag(name:"vuldetect", value:"");
    - script_tag(name:"impact", value:"");
    - script_tag(name:"deprecated", value:"");
    - script_tag(name:"qod", value:"");
    - script_tag(name:"severity_vector", value:"");
    - script_tag(name:"severity_origin", value:"");
    - script_tag(name:"severity_date", value:"");
    - script_tag(name:"solution_method", value:"");
    # nb: Not fully implemented in GVM yet (further implementation "on hold").
    """

    name = "check_valid_script_tag_names"

    @staticmethod
    def run(nasl_file: Path, file_content: str):
        """
        Args:
            nasl_file: The VT that is going to be checked

        Returns:
            tuples: 0 => Success, no message
                -1 => Error, with error message
        """

        found_tags = ""

        allowed_script_tag_names = [
            "solution",
            "solution_type",
            "qod_type",
            "cvss_base",
            "cvss_base_vector",
            "summary",
            "last_modification",
            "insight",
            "affected",
            "creation_date",
            "vuldetect",
            "impact",
            "deprecated",
            "qod",
            "severity_vector",
            "severity_origin",
            "severity_date",
            "solution_method",
        ]

        matches = get_tag_pattern(name=r".+", flags=re.MULTILINE).finditer(
            file_content
        )

        if matches:
            for match in matches:
                if match.group("name") not in allowed_script_tag_names:
                    found_tags += f"\n\t{match.group(0)}"
                    yield LinterError(
                        f"The script_tag name '{match.group('name')}' "
                        "is not allowed.",
                    )

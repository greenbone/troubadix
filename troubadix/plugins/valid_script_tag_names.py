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
from typing import Iterator

from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class AllScriptTagsPattern:
    instance = False

    def __init__(self) -> None:

        self.pattern = re.compile(
            pattern=(
                r'script_tag\(\s*name\s*:\s*(?P<quote>[\'"])'
                r"(?P<name>[a-zA-Z0-9\s\+\-\_]+)(?P=quote)\s*.+\s*\)\s*;"
            ),
            # flags=re.MULTILINE, # It seems that there is no multiline
            # script_tag here
        )
        self.instance = self


def get_all_tag_patterns() -> re.Pattern:
    """Get all script tags **without** matching the value!!!"""
    if AllScriptTagsPattern.instance:
        return AllScriptTagsPattern.instance.pattern
    return AllScriptTagsPattern().pattern


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

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """
        Args:
            nasl_file: The VT that is going to be checked
        """
        if nasl_file.suffix == ".inc":
            return

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

        matches = get_all_tag_patterns().finditer(file_content)

        if matches:
            for match in matches:
                # print(match)
                if match.group("name") not in allowed_script_tag_names:
                    yield LinterError(
                        f"The script_tag name '{match.group('name')}' "
                        "is not allowed.",
                        file=nasl_file,
                        plugin=self.name,
                    )

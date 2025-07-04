# Copyright (C) 2022 Greenbone AG
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
from typing import Iterator

from troubadix.helper.patterns import (
    ScriptTag,
    SpecialScriptTag,
    get_script_tag_pattern,
    get_special_script_tag_pattern,
)
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult

MANDATORY_TAGS = [
    ScriptTag.SUMMARY,
    ScriptTag.CVSS_BASE,
    ScriptTag.CVSS_BASE_VECTOR,
]

MANDATORY_SPECIAL_TAGS = [
    SpecialScriptTag.NAME,
    SpecialScriptTag.VERSION,
    SpecialScriptTag.CATEGORY,
    SpecialScriptTag.FAMILY,
    SpecialScriptTag.COPYRIGHT,
]


class CheckScriptTagsMandatory(FileContentPlugin):
    name = "check_script_tags_mandatory"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """
        This script checks for the existence of the following
        mandatory tags:
        - summary
        and special tags:
        - script_name
        - script_version
        - script_category
        - script_family
        - script_copyright
        """
        if (
            nasl_file.suffix == ".inc"
            or "# troubadix: disable=template_nd_test_files_fps" in file_content
        ):
            return

        for tag in MANDATORY_TAGS:
            if not get_script_tag_pattern(tag).search(file_content):
                yield LinterError(
                    "VT does not contain the following mandatory tag: "
                    f"'script_{tag.value}'",
                    file=nasl_file,
                    plugin=self.name,
                )

        for special_tag in MANDATORY_SPECIAL_TAGS:
            if not get_special_script_tag_pattern(special_tag).search(
                file_content
            ):
                yield LinterError(
                    "VT does not contain the following mandatory tag: "
                    f"'script_{special_tag.value}'",
                    file=nasl_file,
                    plugin=self.name,
                )

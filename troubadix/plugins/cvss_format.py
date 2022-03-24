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

from pathlib import Path
from typing import Iterator

from troubadix.helper import ScriptTag, get_script_tag_pattern
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class CheckCVSSFormat(FileContentPlugin):
    name = "check_cvss_format"

    @staticmethod
    def run(
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        if nasl_file.suffix == ".inc":
            return

        cvss_base_pattern = get_script_tag_pattern(ScriptTag.CVSS_BASE)
        cvss_base_vector_pattern = get_script_tag_pattern(
            ScriptTag.CVSS_BASE_VECTOR
        )

        cvss_detect = cvss_base_pattern.search(file_content)
        if not cvss_detect:
            yield LinterError("VT has a missing or invalid cvss_base value.")

        vector_match = cvss_base_vector_pattern.search(file_content)

        if not vector_match:
            yield LinterError(
                "VT has a missing or invalid cvss_base_vector value."
            )

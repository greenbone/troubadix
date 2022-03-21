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
from typing import Iterator, OrderedDict

from troubadix.helper import ScriptTag
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class CheckCVSSFormat(FileContentPlugin):
    name = "check_cvss_format"

    @staticmethod
    def run(
        nasl_file: Path,
        file_content: str,
        *,
        tag_pattern: OrderedDict[str, re.Pattern],
        special_tag_pattern: OrderedDict[str, re.Pattern],
    ) -> Iterator[LinterResult]:
        del special_tag_pattern
        if nasl_file.suffix == ".inc":
            return

        cvss_detect = tag_pattern[ScriptTag.CVSS_BASE.value]
        cvss_detect = cvss_detect.search(file_content)
        if not cvss_detect:
            yield LinterError("VT has a missing or invalid cvss_base value.")

        vector_match = tag_pattern[ScriptTag.CVSS_BASE_VECTOR.value]
        vector_match = vector_match.search(file_content)

        if not vector_match:
            yield LinterError(
                "VT has a missing or invalid cvss_base_vector value."
            )

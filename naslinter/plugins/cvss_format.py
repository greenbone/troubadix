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

from naslinter.plugin import LinterError, FileContentPlugin, LinterResult


class CheckCVSSFormat(FileContentPlugin):
    name = "check_cvss_format"

    @staticmethod
    def run(nasl_file: Path, file_content: str) -> Iterator[LinterResult]:
        score_match = re.search(
            r'(script_tag\(\s*name\s*:\s*"cvss_base"\s*,\s*value\s*:\s*")'
            r'\d{1,2}\.\d"\s*\)\s*;',
            file_content,
        )
        if score_match is None or score_match.group(0) is None:
            yield LinterError(
                f"VT '{nasl_file}' has a missing or invalid cvss_base value."
            )

        vector_match = re.search(
            r'(script_tag\(\s*name\s*:\s*"cvss_base_vector"\s*,\s*value'
            r'\s*:\s*")AV:[LAN]\/AC:[HML]\/Au:[NSM]\/C:[NPC]\/I:[NPC]\/A:[NPC]"'
            r"\s*\)\s*;",
            file_content,
        )

        if vector_match is None or vector_match.group(0) is None:
            yield LinterError(
                f"VT '{nasl_file}' has a missing or invalid cvss_base_vector "
                "value."
            )

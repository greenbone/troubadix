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

# pylint: disable=fixme

import re
from pathlib import Path
from typing import Iterator

from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class CheckDeprecatedFunctions(FileContentPlugin):
    name = "check_deprecated_functions"

    @staticmethod
    def run(
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """
        Following functions / description items are outdated:
        script_summary()
        script_id()
        security_note()
        security_warning()
        security_hole()
        script_description()
        script_tag("risk_factor", SEVERITY);

        This script checks if any of those are used

        Args:
            nasl_file: Name of the VT to be checked
        """
        deprecated_functions = {
            "script_summary(), use script_tag"
            '(name:"summary", value:"") instead': r"script_summary\s*\([^)]*\)",
            "script_id(), use script_oid() with "
            "the full OID instead": r"script_id\s*\([0-9]+\)",
            "security_note()": r"security_note\s*\([^)]*\)",
            "security_warning()": r"security_warning\s*\([^)]*\)",
            "security_hole()": r"security_hole\s*\([^)]*\)",
            "script_description()": r"script_description\s*\([^)]*\)",
            'script_tag(name:"risk_factor", value: '
            "SEVERITY)": r'script_tag\s*\(\s*name:\s*"risk_factor"[^)]*\)',
        }

        for description, pattern in deprecated_functions.items():
            if re.search(pattern, file_content):
                yield LinterError(
                    f"Found a deprecated function call: {description}"
                )

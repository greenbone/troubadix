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

import re
from typing import Iterator

from troubadix.plugin import FilePlugin, LinterError, LinterResult


class CheckDeprecatedFunctions(FilePlugin):
    name = "check_deprecated_functions"

    def run(self) -> Iterator[LinterResult]:
        """
        Following functions / description items are deprecated:
        script_summary()
        script_id()
        security_note()
        security_warning()
        security_hole()
        script_description()
        script_tag(name:"risk_factor", value:"SEVERITY");
        script_bugtraq_id()

        This script checks and reports if any of those are used

        Args:
            nasl_file: Name of the VT to be checked
        """
        deprecated_functions = {
            'script_summary();, use script_tag(name:"summary", value:""); '
            "instead": r"script_summary\s*\([^)]*\);",
            "script_id();, use script_oid(); with "
            "the full OID instead": r"script_id\s*\([0-9]+\);",
            "security_note();": r"security_note\s*\([^)]*\);",
            "security_warning();": r"security_warning\s*\([^)]*\);",
            "security_hole();": r"security_hole\s*\([^)]*\);",
            "script_description();": r"script_description\s*\([^)]*\);",
            'script_tag(name:"risk_factor", value:'
            '"SEVERITY");': r'script_tag\s*\(\s*name:\s*"risk_factor"[^)]*\);',
            "script_bugtraq_id();": r"script_bugtraq_id\s*\([^)]*\);",
        }

        for description, pattern in deprecated_functions.items():
            if re.search(pattern, self.context.file_content, re.MULTILINE):
                yield LinterError(
                    "Found a deprecated function call / description item: "
                    f"{description}",
                    file=self.context.nasl_file,
                    plugin=self.name,
                )

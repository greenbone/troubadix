# Copyright (C) 2021 Greenbone AG
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


class CheckVariableAssignedInIf(FileContentPlugin):
    """This script checks the passed VT/Include if it is using
    a variable assignment within an if() call like e.g.:

    if( variable = "content" ) {}

    instead of:

    if( variable =~ "content" ) {}
    if( variable == "content" ) {}
    """

    name = "check_variable_assigned_in_if"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """
        Args:
            file: The VT/Include that is going to be checked

        Returns:
        """
        # TO DO: Find a better way to parse if calls as this would
        # miss something like e.g.:
        #
        # if((foo =~ "bar" || bar =~ "foo") || foobar = "foo"){}
        #
        # nb: We can't use { as an ending delimiter as there could
        # be also something like e.g.:
        #
        # if((foo =~ "bar || bar =~ "foo") || foobar = "foo")
        #   bar = "foo"; (no ending {)
        matches = re.finditer(
            r"^\s*(if|}?\s*else if)\s*\(([^)]+)", file_content, re.MULTILINE
        )
        if matches is None:
            return

        lint_error = False
        output = (
            f"VT/Include '{nasl_file.name}' is using a variable assignment"
            " within an if() call in the following line(s):\n"
        )

        for match in matches:
            if match is not None and match.group(1) is not None:
                var_assign_match = re.search(
                    r"((if|}?\s*else if)\s*\(\s*?|\|{2}\s*|&{2}\s*)"
                    r'[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*("|\'|TRUE|0|1)',
                    match.group(0),
                )
                if (
                    var_assign_match is not None
                    and var_assign_match.group(1) is not None
                ):
                    # nb: Can't be fixed because it would mean a change
                    # of a default behavior.
                    if (
                        "policy_file_checksums_win.nasl" in nasl_file.name
                        and "install = " in match.group(0)
                    ):
                        continue

                    output = f"{output} {match.group(0)}\n"
                    lint_error = True

        if lint_error:
            yield LinterError(
                output,
                file=nasl_file,
                plugin=self.name,
            )

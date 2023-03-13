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

from troubadix.helper import is_ignore_file
from troubadix.helper.patterns import ScriptTag, get_script_tag_pattern
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult

# We don't want to touch the metadata of this older VTs...
_IGNORE_FILES = [
    "nmap_nse/",
]


class CheckMissingTagSolution(FileContentPlugin):
    name = "check_missing_tag_solution"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """This script checks if the VT has a solution_type script tag:
        script_tag(name:"solution_type", value:"");

        but is missing a solution tag within the description block like:
        script_tag(name:"solution", value:"");

        This excludes files from the (sub)dir "nmap_nse/" and deprecated
        vts.
        """

        if nasl_file.suffix == ".inc":
            return

        if is_ignore_file(nasl_file, _IGNORE_FILES):
            return

        # Not all VTs have/require a solution_type text
        if "solution_type" not in file_content:
            return

        # Avoid unnecessary message against deprecated VTs.
        deprecated_pattern = get_script_tag_pattern(ScriptTag.DEPRECATED)
        deprecated_match = deprecated_pattern.search(string=file_content)

        if deprecated_match and deprecated_match.group("value"):
            return

        solution_type_pattern = get_script_tag_pattern(ScriptTag.SOLUTION_TYPE)
        solution_type_match = solution_type_pattern.search(string=file_content)
        if not solution_type_match:
            return

        solution_pattern = get_script_tag_pattern(ScriptTag.SOLUTION)
        solution_match = solution_pattern.search(string=file_content)

        if not solution_match or solution_match.group(0) is None:
            yield LinterError(
                "'solution_type' script_tag but no 'solution' script_tag "
                "found in the description block.",
                file=nasl_file,
                plugin=self.name,
            )

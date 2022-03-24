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
from typing import Iterable, Iterator

from troubadix.plugin import LineContentPlugin, LinterResult, LinterWarning


class CheckNewlines(LineContentPlugin):
    name = "check_wrong_newlines"

    @staticmethod
    def run(
        nasl_file: Path,
        lines: Iterable[str],
    ) -> Iterator[LinterResult]:
        """This script FIXES newline errors:
        - Checking the passed VT for the existence of newlines in
          the script_name() and script_copyright() tags.
        - Removes wrong newline indicators (\r or \r\n).
        - Removes whitespaces in script_name( "myname") or script_copyright
        """
        # This "hack" guarantees, that we only have "\n" as newlines
        # since we
        content = "\n".join(lines)

        # A few remaining have script_name( "myname") instead of
        # script_name("myname").
        # NEW: Remove whitespaces and newlines in script_name, script_copyright
        for tag in ["name", "copyright"]:
            remove_whitespaces_match = re.search(
                rf'script_{tag}\s*\(\s*[\'"](.*)[\'"]\)\s*\)\s*;', content
            )
            if remove_whitespaces_match:
                content.replace(
                    remove_whitespaces_match.group(0),
                    f'script_{tag}("{remove_whitespaces_match.group(1)}");',
                )
                yield LinterWarning(
                    "Removed whitespaces in "
                    f"{remove_whitespaces_match.group(0)}"
                )

            newline_match = re.search(
                rf'(script_{tag}\([\'"][^\'"\n;]*)[\n]+\s*([^\'"\n;]*[\'"]\);)',
                content,
            )
            if newline_match:
                content = content.replace(
                    newline_match.group(0),
                    f"{newline_match.group(1)}{newline_match.group(2)}",
                )
                yield LinterWarning(
                    f"Removed a newline within the tag script_{tag}."
                )

        nasl_file.write_text(content, encoding="latin1")

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
from troubadix.helper import CURRENT_ENCODING
from troubadix.plugin import FileContentPlugin, LinterResult, LinterError


class CheckNewlines(FileContentPlugin):
    name = "check_wrong_newlines"

    @staticmethod
    def run(
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """This script FIXES newline errors:
        - Checking the passed VT for the existence of newlines in
          the script_name() and script_copyright() tags.
        - Search for (\r or \r\n).
        - Search for whitespaces in script_name( "myname") or script_copyright
        """
        # Need to be loaded as bytes or \r is converted to \n
        data = nasl_file.read_bytes().decode(CURRENT_ENCODING)
        if "\r" in data or "\r\n" in data:
            yield LinterError("Found \\r or \\r\\n newline.")

        # A few remaining have script_name( "myname") instead of
        # script_name("myname").
        # NEW: Remove whitespaces and newlines in script_name, script_copyright
        for tag in ["name", "copyright"]:
            whitespaces_match = re.search(
                rf'script_{tag}(?P<w1>\s*)\((?P<w2>\s*)(?P<quote>[\'"])'
                r"?.+?(?P=quote)?(?P<w3>\s*)\)(?P<w4>\s*);",
                file_content,
            )
            if whitespaces_match:
                for i in range(1, 5):
                    if whitespaces_match.group(f"w{i}") != "":
                        yield LinterError(f"Found whitespaces in script_{tag}.")
                        break

            newline_match = re.search(
                rf'(script_{tag}\((?P<quote>[\'"])[^\'"\n;]*)[\n]+\s*'
                r'([^\'"\n;]*(?P=quote)\);)',
                file_content,
            )
            if newline_match:
                yield LinterError(
                    f"Found a newline within the tag script_{tag}."
                )

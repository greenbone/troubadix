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

from naslinter.helper import is_ignore_file

from naslinter.plugin import (
    LineContentPlugin,
    LinterError,
    LinterResult,
    LinterWarning,
)

# We don't want to touch the metadata of this older VTs...
_IGNORE_FILES = [
    "nmap_nse/",
]


class CheckWrongNewlines(LineContentPlugin):
    name = "check_wrong_newlines"

    def run(
        self, nasl_file: Path, lines: Iterable[str]
    ) -> Iterator[LinterResult]:
        self.lines = lines
        self._has_wrong_newlines()
        self._has_unallowed_newlines_in_script_tags()

        nasl_file.write_text("".join(self.lines), encoding="latin1")

    def _has_wrong_newlines(self):
        """This script checks the passed VT for the existence of CRLF and CR newlines.
        An error will be thrown if the newlines are incorrectly formatted. Only UNIX newlines (LF) are valid.

        New: This already replaces the newlines infile!!!

        Args:
            nasl_file: The VT that is going to be checked

        """
        affected = ""

        for index, line in enumerate(self.lines):
            if line[-2:] == "\r\n":
                # remove last char
                line = line[:-1]
            if line[-1] == "\r":
                # replace last char
                line[-1] = "\n"
                yield LinterWarning(
                    f"Wrong newline (CR/CRLF) detected in line {index}, converted to LF"
                )
                break

    def _has_unallowed_newlines_in_script_tags(self):
        """This script checks the passed VT for the existence of newlines in the script_name() and script_copyright() tags.
        An error will be thrown if newlines have been found in the aforementioned tags.

        Args:
            nasl_file: The VT that is going to be checked

        Returns:
            tuples: 0 => Success, no message
                -1 => Error, with error message

        """

        err = False
        name = ""
        copyright = ""

        name_tag_match = re.search(
            r'script_name\s*\(\s*[\'"]([^\n]+)[\'"]\s*\)\s*;', content
        )
        name_tag_match = re.search(
            r'script_name\s*\([\'"]([^\n]+)[\'"]\s*\)\s*;', content
        )
        # TODO: A few remaining have script_name( "myname"), use the following instead of
        # the above once those where migrated to script_name("myname") and remote the
        # "not in" handling below as well.

        copyright_tag_macth = re.search(
            r'script_copyright\s*\([\'"]([^\n]+)[\'"]\s*\)\s*;', content
        )

        if name_tag_match is None and "script_name(name);" not in content:
            err = True
            name = "- script_name()"
        if copyright_tag_macth is None:
            err = True
            copyright = "- script_copyright()"

        if err:
            return (
                -1,
                "VT '"
                + str(nasl_file)
                + "' contains a script_tag with an unallowed newline.\nPlease remove the newline out of the following tag(s): "
                + name
                + " "
                + copyright
                + ".",
            )
        return (0,)

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
from typing import Iterator, Union

from troubadix.helper import CURRENT_ENCODING
from troubadix.helper.patterns import get_common_tag_patterns
from troubadix.plugin import FilePlugin, LinterFix, LinterResult, LinterWarning

# import magic


# ;                 can not be displayed in GSA, within
#                   (summary|impact|affected|insight|vuldetect|solution)
# | =               are delimiter in the internal VT cache
#                   (e.g. Tag1=Foo|Tag2=Bar|Tag3=Baz)
#                   in all script_tag(name:"", value:"")
FORBIDDEN_CHARS = ["|", "=", ";"]

# replacement character will be a whitespace
REPLACE_CHAR = " "


def check_match(match: re.Match) -> Union[str, None]:
    """Replace all FORBIDDEN characters with the replace character defined.
    Returns:
        The fixed string or None"""
    if match and match.group("value") is not None:
        changes: bool = False
        line: str = match.group(0)
        value: str = match.group("value")
        for char in FORBIDDEN_CHARS:
            if char in value:
                changes = True
                value = value.replace(char, REPLACE_CHAR)
        if changes:
            return line.replace(match.group("value"), value)
    return None


class CheckIllegalCharacters(FilePlugin):
    name = "check_illegal_characters"

    def run(self) -> Iterator[LinterResult]:
        """
        Currently the following chars are not allowed in
        every script_tag(name:"", value:"") :
        """

        if self.context.nasl_file.suffix == ".inc":
            return

        pattern = get_common_tag_patterns()
        file_content = self.context.file_content

        self.new_file_content = None

        tag_matches = pattern.finditer(file_content)
        if tag_matches:
            for match in tag_matches:
                if match and match.group(0) is not None:
                    new_tag = check_match(match)
                    if new_tag:
                        file_content = file_content.replace(
                            match.group(0), new_tag
                        )
                        self.new_file_content = file_content
                        yield LinterWarning(
                            f"Found illegal character in {match.group(0)}",
                            file=self.context.nasl_file,
                            plugin=self.name,
                        )

    def fix(self) -> Iterator[LinterResult]:
        if not self.new_file_content:
            return

        self.context.nasl_file.write_text(
            self.new_file_content, encoding=CURRENT_ENCODING
        )

        yield LinterFix(
            "Replaced Illegal Characters.",
            file=self.context.nasl_file,
            plugin=self.name,
        )

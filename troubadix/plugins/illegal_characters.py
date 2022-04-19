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

from typing import Iterator, List, Union

from troubadix.helper.patterns import get_common_tag_patterns
from troubadix.plugin import LinterResult, LinterWarning, FilePlugin

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
        pattern = get_common_tag_patterns()
        file_content = self.context.file_content

        tag_matches: List[re.Match] = pattern.finditer(file_content)
        if tag_matches:
            for match in tag_matches:
                if match and match.group(0) is not None:
                    new_tag = check_match(match)
                    if new_tag:
                        # changes = True
                        yield LinterWarning(
                            f"Found illegal character in {match.group(0)}"
                        )
                        file_content = file_content.replace(
                            match.group(0), new_tag
                        )

        # if changes:
        #     nasl_file.write_text(file_content, encoding=CURRENT_ENCODING)

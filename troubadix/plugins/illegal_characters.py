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
from typing import Iterator, List

from troubadix.helper import CURRENT_ENCODING
from troubadix.helper.patterns import get_common_tag_patterns
from troubadix.plugin import (
    FilePlugin,
    LinterError,
    LinterFix,
    LinterResult,
    LinterWarning,
)

# import magic


# ;                 can not be displayed in GSA, within
#                   (summary|impact|affected|insight|vuldetect|solution)
# | =               are delimiter in the internal VT cache
#                   (e.g. Tag1=Foo|Tag2=Bar|Tag3=Baz)
#                   in all script_tag(name:"", value:"")
FORBIDDEN_CHARS = ["|", ";"]
WARNING_CHARS = ["="]

# replacement character will be a whitespace
REPLACE_CHAR = " "


def check_forbidden(match: re.match) -> List[str]:
    """Check the given tag for forbidden characters

    Args:
        match (re.match): The tag to check

    Returns:
        List[str]: The list of forbidden characters that were found
    """
    return [
        f"'{char}'" for char in FORBIDDEN_CHARS if char in match.group("value")
    ]


def fix_forbidden(
    match: re.Match, found_forbidden_characters: List[str]
) -> str:
    """Returns the fixed version of the tag with
       the forbidden characters replaced

    Args:
        match (re.Match): The tag containing forbidden characters
        found_forbidden_characters (List[str]): The list of forbidden
                                                characters found

    Returns:
        str: The sanitized tag
    """
    line: str = match.group(0)
    value: str = match.group("value")
    for char in found_forbidden_characters:
        value = value.replace(char, REPLACE_CHAR)
    return line.replace(match.group("value"), value)


def check_warning(match: re.Match) -> List[str]:
    """Checks the given tag for warning characters

    Args:
        match (re.Match): The tag to check

    Returns:
        List[str]: The list of warning characters found
    """
    return [
        f"'{char}'" for char in WARNING_CHARS if char in match.group("value")
    ]


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

        self.new_file_content = None

        tag_matches = pattern.finditer(self.context.file_content)
        if tag_matches:
            for match in tag_matches:
                if match and match.group(0) is not None:

                    found_forbidden_characters = check_forbidden(match)
                    if found_forbidden_characters:
                        self.new_file_content = (
                            self.context.file_content.replace(
                                match.group(0),
                                fix_forbidden(
                                    match, found_forbidden_characters
                                ),
                            )
                        )

                        yield LinterError(
                            "Found illegal characters "
                            f"[{', '.join(found_forbidden_characters)}] "
                            f"in {match.group(0)}",
                            file=self.context.nasl_file,
                            plugin=self.name,
                        )

                    found_warning_characters = check_warning(match)
                    if found_warning_characters:
                        yield LinterWarning(
                            "Found characters "
                            f"[{', '.join(found_warning_characters)}] "
                            f"in {match.group(0)}",
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

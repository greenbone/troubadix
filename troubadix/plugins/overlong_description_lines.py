#  Copyright (c) 2024 Greenbone AG
#
#  SPDX-License-Identifier: GPL-3.0-or-later
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
from pathlib import Path
from typing import Iterator

from troubadix.plugin import (
    FileContentPlugin,
    LinterError,
    LinterResult,
    LinterWarning,
)

DESCRIPTION_START_PATTERN = re.compile(r"if\s*\(\s*description\s*\)")
DESCRIPTION_END_PATTERN = re.compile(r"exit\(0\);")
IGNORE_TAGS = [
    "script_name",
    "script_xref",
    "script_add_preference",
    # nb: Special case we should ignore (at least for now) as it is commonly
    # used like this and is only two chars "too long".
    'script_tag(name:"vuldetect", value:"Checks if a vulnerable version is '
    + 'present on the target host.");',
]


class CheckOverlongDescriptionLines(FileContentPlugin):
    """This step checks if a VT contains lines in the description block
    that are longer than 100 characters.
    """

    name = "check_overlong_description_lines"

    def check_content(
        self, nasl_file: Path, file_content: str
    ) -> Iterator[LinterResult]:
        if nasl_file.suffix == ".inc":
            return

        if not (start_match := DESCRIPTION_START_PATTERN.search(file_content)):
            yield LinterError(
                "Check failed. Unable to find start of description block",
                plugin=self.name,
                file=nasl_file,
            )
        if not (end_match := DESCRIPTION_END_PATTERN.search(file_content)):
            yield LinterError(
                "Check failed. Unable to find end of description block",
                plugin=self.name,
                file=nasl_file,
            )

        if not start_match or not end_match:
            return

        line_offset = file_content[: start_match.start()].count("\n")
        description_block = file_content[start_match.start() : end_match.end()]
        lines = description_block.splitlines()
        for i, line in enumerate(lines, 1 + line_offset):
            if len(line) > 100:
                if any(tag in line for tag in IGNORE_TAGS):
                    continue

                yield LinterWarning(
                    f"Line {i} is too long"
                    f" with {len(line)} characters. "
                    f"Max 100",
                    plugin=self.name,
                    file=nasl_file,
                    line=i,
                )

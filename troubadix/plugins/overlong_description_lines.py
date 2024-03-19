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

from pathlib import Path
from typing import Iterable, Iterator

from troubadix.plugin import (
    LineContentPlugin,
    LinterError,
    LinterResult,
    LinterWarning,
)


class CheckOverlongDescriptionLines(LineContentPlugin):
    """This step checks if a VT contains lines in the description block
    that are longer than 100 characters.
    """

    name = "check_overlong_description_lines"

    def check_lines(
        self,
        nasl_file: Path,
        lines: Iterable[str],
    ) -> Iterator[LinterResult]:
        if nasl_file.suffix == ".inc":
            return

        description_starts = [
            "if(description)",
            "if (description)",
            "if( description )",
            "if(description )",
        ]
        description_end = "exit(0);"
        found_start = False
        found_end = False
        ignore_tags = ["script_name"]
        results = []
        for i, line in enumerate(lines, 1):

            if not found_start and any(
                description_start in line
                for description_start in description_starts
            ):
                found_start = True
                continue

            if not found_end and description_end in line:
                found_end = True
                break

            if found_start:
                if len(line) > 100:
                    if any(ignore_tag in line for ignore_tag in ignore_tags):
                        continue

                    results.append(
                        LinterWarning(
                            f"Line {i} is too long"
                            f" with {len(line)} characters. "
                            f"Max 100",
                            plugin=self.name,
                            file=nasl_file,
                            line=i,
                        )
                    )
        if not found_start:
            yield LinterError(
                "Check failed. Unable to find start of description block",
                plugin=self.name,
                file=nasl_file,
            )
        if not found_end:
            yield LinterError(
                "Check failed. Unable to find end of description block",
                plugin=self.name,
                file=nasl_file,
            )
        if found_start and found_end:
            yield from results

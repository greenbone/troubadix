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

from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator

from naslinter.plugin import LineContentPlugin, LinterError, LinterResult

LENGTH = 44


class CheckCreationDate(LineContentPlugin):
    name = "creation_date"

    @staticmethod
    def run(nasl_file: Path, lines: Iterable[str]) -> Iterator[LinterResult]:
        for line in lines:
            if "creation_date" in line:
                # Example: "2017-11-29 13:56:41 +0100 (Wed, 29 Nov 2017)"
                mod_pattern = (
                    r"script_tag\(name:\"creation_date\", "
                    r"value:\"(([0-9:\s-]+\+[0-9]+)\s\((.+)\))\"\);"
                )

                match = re.search(pattern=mod_pattern, string=line)
                if match:
                    # Check length of the datetime value
                    if len(match.group(1)) != LENGTH:
                        yield LinterError(
                            "Incorrectly formatted creation_date of VT "
                            f"'{nasl_file}' (length != {LENGTH}). Please "
                            'use EXACTLY the following format as in: "2017'
                            '-11-29 13:56:41 +0000 (Wed, 29 Nov 2017)"'
                        )
                        return
                    try:
                        date_left = datetime.strptime(
                            match.group(2), "%Y-%m-%d %H:%M:%S %z"
                        )
                        # 2017-11-29 13:56:41 +0100 (error if no timezone)
                        date_right = datetime.strptime(
                            match.group(3), "%a, %d %b %Y"
                        )
                        week_day_parsed = date_right.strftime("%a")
                    except ValueError:
                        yield LinterError(
                            f"False or incorrectly formatted creation_date "
                            f"of VT '{nasl_file}'"
                        )
                        return
                    week_day_str = match.group(3)[:3]
                    # Wed, 29 Nov 2017
                    if date_left.date() != date_right.date():
                        yield LinterError(
                            f"The creation_date of VT '{nasl_file}' "
                            "consists of two different dates."
                        )
                    # Check correct weekday
                    elif week_day_str != week_day_parsed:
                        formatted_date = week_day_parsed
                        yield LinterError(
                            f"Wrong day of week in VT '{nasl_file}'. "
                            f"Please change it from '{week_day_str}' to "
                            f"'{formatted_date}'."
                        )
                else:
                    yield LinterError(
                        f"False or incorrectly formatted creation_date "
                        f"of VT '{nasl_file}'"
                    )
                return

        yield LinterError(
            f"No creation date has been found in VT '{nasl_file}'."
        )

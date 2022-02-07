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

from ..plugin import LineContentPlugin, LinterError, LinterResult


class CheckCreationDate(LineContentPlugin):
    name = "creation_date"

    @staticmethod
    def run(nasl_file: Path, lines: Iterable[str]) -> Iterator[LinterResult]:
        for line in lines:
            if not "creation_date" in line:
                continue

            expression = re.search(r'value\s*:\s*"(.*)"', line)
            if expression:
                creation_date = expression.group(1)
                # Example: "2017-11-29 13:56:41 +0100 (Wed, 29 Nov 2017)"
                if creation_date:
                    try:
                        values = re.match(r"([^\(]+)\(([^\)]+)", creation_date)
                        date_left = datetime.strptime(
                            values.group(1).strip(), "%Y-%m-%d %H:%M:%S %z"
                        )
                        # 2017-11-29 13:56:41 +0100 (error if no timezone)
                        date_right = datetime.strptime(
                            values.group(2).strip(), "%a, %d %b %Y"
                        )
                        # Wed, 29 Nov 2017
                        if date_left.date() != date_right.date():
                            yield LinterError(
                                f"The creation_date of VT '{nasl_file}' "
                                "consists of two different dates."
                            )

                        elif values.group(2).strip()[:3] != date_right.strftime(
                            "%a"
                        ):
                            formatted_date = date_left.strftime("%a")
                            yield LinterError(
                                f"Wrong day of week in VT '{nasl_file}'. "
                                f"Please change it from "
                                f"'{values.group(2).strip()[:3]}' to "
                                f"'{formatted_date}'."
                            )

                        if len(creation_date) != 44:
                            yield LinterError(
                                f"Incorrectly formatted creation_date of "
                                f"VT '{nasl_file}' (length != 44). Please "
                                f"use EXACTLY the following format as in: "
                                f'"2017-11-29 13:56:41 +0000 '
                                f'(Wed, 29 Nov 2017)"'
                            )

                    except ValueError:
                        yield LinterError(
                            f"False or incorrectly formatted creation_date "
                            f"of VT '{nasl_file}'"
                        )

                    return

        yield LinterError(
            f"No creation date has been found in VT '{nasl_file}'."
        )

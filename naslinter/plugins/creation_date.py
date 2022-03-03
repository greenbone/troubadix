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
from typing import Iterable, Iterator, OrderedDict
from naslinter.helper.patterns import ScriptTag

from naslinter.plugin import FileContentPlugin, LinterError, LinterResult

LENGTH = 44


class CheckCreationDate(FileContentPlugin):
    name = "creation_date"

    @staticmethod
    def run(
        nasl_file: Path,
        file_content: str,
        *,
        tag_pattern: OrderedDict[str, re.Pattern],
        special_tag_pattern: OrderedDict[str, re.Pattern],
    ) -> Iterator[LinterResult]:
        if nasl_file.suffix == ".inc":
            return

        # Example: "2017-11-29 13:56:41 +0100 (Wed, 29 Nov 2017)"
        mod_pattern = tag_pattern[ScriptTag.CREATION_DATE.value]

        match = mod_pattern.search(string=file_content)
        if match:
            # Check length of the datetime value
            if len(match.group("value")) != LENGTH:
                yield LinterError(
                    "Incorrectly formatted creation_date of VT "
                    f"'{nasl_file}' (length != {LENGTH}). Please "
                    'use EXACTLY the following format as in: "2017'
                    '-11-29 13:56:41 +0000 (Wed, 29 Nov 2017)"'
                )
                return
            try:
                date_left = datetime.strptime(
                    match.group("value")[:25], "%Y-%m-%d %H:%M:%S %z"
                )
                # 2017-11-29 13:56:41 +0100 (error if no timezone)
                date_right = datetime.strptime(
                    match.group("value")[27:43], "%a, %d %b %Y"
                )
                week_day_parsed = date_right.strftime("%a")
            except ValueError:
                yield LinterError(
                    f"False or incorrectly formatted creation_date "
                    f"of VT '{nasl_file}'"
                )
                return
            week_day_str = match.group("value")[27:30]
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

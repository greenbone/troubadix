#  Copyright (c) 2022 Greenbone Networks GmbH
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
from typing import Iterable, Iterator

from troubadix.plugin import LineContentPlugin, LinterError, LinterResult


class CheckDescription(LineContentPlugin):
    name = "check_description"

    @staticmethod
    def run(
        nasl_file: Path,
        lines: Iterable[str],
    ) -> Iterator[LinterResult]:

        """This script checks if some NVTs are still using script_description

        Args:
            nasl_file:    The VT / Include that is going to be checked
            file_content: The content of the file that is going to be
                          checked
        """
        pattern = re.compile(r"script_description\(.+\);", re.IGNORECASE)

        for line in lines:
            match = pattern.search(line)
            if match:
                yield LinterError(
                    "VT/Include is using deprecated 'script_description':"
                    f" {line}"
                )

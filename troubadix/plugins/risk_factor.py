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
from typing import Iterator

from troubadix.plugin import FileContentPlugin, LinterResult, LinterError


class CheckRiskFactor(FileContentPlugin):
    name = "risk_factor"

    @staticmethod
    def run(
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """This script checks if a VT with risk_factor tag exist."""
        match = re.search(
            r'script_tag\(name:"risk_factor", value:"(?P<risk>.+)"\);',
            file_content,
        )

        if not match:
            return

        yield LinterError(
            f'Deprecated function "risk factor" found: {match.group("risk")}'
        )

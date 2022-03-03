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
from naslinter.helper.patterns import get_tag_pattern

from naslinter.plugin import FileContentPlugin, LinterError


class CheckScriptTagForm(FileContentPlugin):
    name = "check_script_tag_form"

    @staticmethod
    def run(_: Path, file_content: str) -> Iterator[LinterError]:
        """
        Checks for correct parameters for script_tag calls
        """
        matches = re.finditer(r"script_tag\(.*\);", file_content)
        for match in matches:
            if match:
                if not get_tag_pattern(name=r".*", value=r".*").match(
                    match.group(0)
                ):
                    yield LinterError(
                        f"{match.group(0)}: does not conform to"
                        ' script_tag(name:"<name>", value:<value>);'
                    )

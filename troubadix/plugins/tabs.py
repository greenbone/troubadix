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

from pathlib import Path
from typing import Iterator

from troubadix.plugin import FileContentPlugin, LinterResult, LinterWarning

TAB_TO_SPACES = 2


class CheckTabs(FileContentPlugin):
    name = "check_tabs"

    @staticmethod
    def run(
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """This script checks if a VT is using one or
        more tabs instead of spaces."""
        if "\t" in file_content:
            file_content = file_content.replace("\t", " " * TAB_TO_SPACES)
            nasl_file.write_text(data=file_content, encoding="latin1")
            yield LinterWarning(
                f"Replaced one or more tabs to {TAB_TO_SPACES} spaces!"
            )

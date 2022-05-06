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

from validators import url

from troubadix.helper.patterns import get_xref_pattern
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class CheckScriptXrefUrl(FileContentPlugin):
    name = "check_script_xref_url"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """
        Checks if a URL type script_xref call contains a valid URL
        """
        if nasl_file.suffix == ".inc":
            return

        matches = get_xref_pattern(name="URL", value=r".+?").finditer(
            file_content
        )
        for match in matches:
            if match:
                if not url(match.group("value")):
                    yield LinterError(
                        f"{match.group(0)}: Invalid URL value",
                        file=nasl_file,
                        plugin=self.name,
                    )

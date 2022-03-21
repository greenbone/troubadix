# Copyright (C) 2021 Greenbone Networks GmbH
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
from typing import Iterator, OrderedDict

from troubadix.helper import (
    ScriptTag,
    SpecialScriptTag,
    get_root,
    get_special_tag_pattern,
    get_tag_pattern,
)
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class CheckVTPlacement(FileContentPlugin):
    """The script checks if the passed VT is using one of the
    two following families:

    - script_family("Service detection");
    - script_family("Product detection");

    and is correctly placed into the "root" of the VTs directory.
    """

    name = "check_vt_placement"

    @staticmethod
    def run(
        nasl_file: Path,
        file_content: str,
        *,
        tag_pattern: OrderedDict[str, re.Pattern],
        special_tag_pattern: OrderedDict[str, re.Pattern],
    ) -> Iterator[LinterResult]:
        """
        Args:
            nasl_file: The VT that shall be checked
            file_content: str representing the file content

        Returns:
            if no problem
        """
        del tag_pattern, special_tag_pattern

        root = get_root(nasl_file)

        match = get_special_tag_pattern(
            name=SpecialScriptTag.FAMILY,
            value=r"(Product|Service) detection",
            flags=re.MULTILINE,
        ).search(file_content)
        if match is None:
            return

        match = get_tag_pattern(name=ScriptTag.DEPRECATED).search(file_content)
        if match is not None:
            return

        # nb: Path depends on the way the check
        # is called (FULL/part run, CI run, ...)
        if (
            root / nasl_file.name == nasl_file
            or root / "gsf" / nasl_file.name == nasl_file
            or root / "attic" / nasl_file.name == nasl_file
        ):
            return

        yield LinterError(
            f"VT should be placed in the root directory ({root}).",
        )

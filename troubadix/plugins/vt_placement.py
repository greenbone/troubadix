# Copyright (C) 2021 Greenbone AG
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
from itertools import chain
from pathlib import Path
from typing import Iterator

from troubadix.helper import ScriptTag, SpecialScriptTag, get_script_tag_pattern
from troubadix.helper.helper import ENTERPRISE_FOLDERS, FEED_VERSIONS
from troubadix.helper.patterns import _get_special_script_tag_pattern
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class CheckVTPlacement(FileContentPlugin):
    """The script checks if the passed VT is using one of the
    two following families:

    - script_family("Service detection");
    - script_family("Product detection");

    and is correctly placed into the "root" of the VTs directory.
    """

    name = "check_vt_placement"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """
        Args:
            nasl_file: The VT that shall be checked
            file_content: str representing the file content

        Returns:
            if no problem
        """

        if nasl_file.suffix == ".inc":
            return

        root = self.context.root

        match = _get_special_script_tag_pattern(
            name=SpecialScriptTag.FAMILY.value,
            value=r"(Product|Service) detection",
            flags=re.MULTILINE,
        ).search(file_content)
        if match is None:
            return

        tag_pattern = get_script_tag_pattern(ScriptTag.DEPRECATED)

        match = tag_pattern.search(file_content)
        if match is not None:
            return

        if any(
            (root / vers / nasl_file.name) == nasl_file
            for vers in FEED_VERSIONS
        ):
            return

        for folder in chain(["attic"], ENTERPRISE_FOLDERS):
            if any(
                (root / vers / folder / nasl_file.name) == nasl_file
                for vers in FEED_VERSIONS
            ):
                return

        yield LinterError(
            f"VT should be placed in the root directory ({root}).",
            file=nasl_file,
            plugin=self.name,
        )

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

from pathlib import Path
import re

from ..plugin import LinterError, FileContentPlugin


class CheckCopyRightYearPlugin(FileContentPlugin):
    """The script checks if the passed VT is using one of the
    two following families:

    - script_family("Service detection");
    - script_family("Product detection");

    and is correctly placed into the "root" of the VTs directory.
    """

    @staticmethod
    def run(nasl_file: Path, file_content: str):
        """
        Args:
            nasl_file: The VT that shall be checked
            file_content: str representing the file content

        Returns:
            if no problem
        """

        match = re.search(
            r'^\s*script_family\s*\(\s*"(Product|Service) detection"\s*\)\s*;',
            file_content,
            re.MULTILINE,
        )
        if match is None:
            return

        match = re.search(
            r'^\s*script_tag\s*\(\s*name\s*:\s*[\'"]deprecated[\'"]'
            r"\s*,\s*value\s*:\s*TRUE\s*\)\s*;",
            file_content,
            re.MULTILINE,
        )
        if match is not None:
            return

        # nb: Path depends on the way the check
        # is called (FULL/part run, CI run, ...)
        if (
            nasl_file.name == nasl_file
            or Path(f"./{nasl_file.name}") == nasl_file
            or Path(f"scripts/{nasl_file.name}") == nasl_file
            or Path(f"./scripts/{nasl_file.name}") == nasl_file
            or Path(f"gsf/{nasl_file.name}") == nasl_file
            or Path(f"./gsf/{nasl_file.name}") == nasl_file
            or Path(f"scripts/gsf/{nasl_file.name}") == nasl_file
            or Path(f"./scripts/gsf/{nasl_file.name}") == nasl_file
            or Path(f"attic/{nasl_file.name}") == nasl_file
            or Path(f"./attic/{nasl_file.name}") == nasl_file
            or Path(f"scripts/attic/{nasl_file.name}") == nasl_file
            or Path(f"./scripts/attic/{nasl_file.name}") == nasl_file
        ):
            return

        yield LinterError(
            f"VT '{str(nasl_file)}' should be placed in the root directory.\n",
        )

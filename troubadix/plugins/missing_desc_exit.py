#  Copyright (c) 2022 Greenbone AG
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
from typing import Iterator

from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class CheckMissingDescExit(FileContentPlugin):
    name = "check_missing_desc_exit"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """This script checks if a VT is missing an 'exit(0);' within the
        description block like this:

        if(description) {
          *tags*
        }

        which should be the following instead:

        if(description) {
          *tags*
          exit(0);
        }

        Args:
            nasl_file: The VT that is going to be checked
            file_content: The content of the file that is going to be checked

        """
        if (
            nasl_file.suffix == ".inc"
            or "# troubadix: disable=template_nd_test_files_fps" in file_content
        ):
            return

        match = re.search(
            r"^if\s*\(\s*description\s*\)\s*\{(.+?)^\}",
            file_content,
            re.MULTILINE | re.DOTALL,
        )
        if match and match.group(1):
            submatch = re.search(
                r"^\s*exit\s*\(\s*0\s*\)\s*;", match.group(1), re.MULTILINE
            )
            if not submatch:
                yield LinterError(
                    "No mandatory exit(0); found in the description block.",
                    file=nasl_file,
                    plugin=self.name,
                )

            return

        yield LinterError(
            "No description block extracted/found.",
            file=nasl_file,
            plugin=self.name,
        )

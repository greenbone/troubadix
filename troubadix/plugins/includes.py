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

# pylint: disable=fixme

import re
from pathlib import Path
from typing import Iterator

from troubadix.helper import get_root
from troubadix.plugin import (
    FileContentPlugin,
    LinterError,
    LinterResult,
)


class CheckIncludes(FileContentPlugin):
    name = "check_includes"

    @staticmethod
    def run(
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """This script checks if the files used in include()
        exist on the local filesystem.
        An error will be thrown if a dependency could not be found.
        """
        # TODO: add to special_tag_pattern
        matches = re.compile(
            r'include\s*\([\'"]?(?P<value>.+?)[\'"]?\s*\)\s*;'
        ).finditer(file_content)

        root = get_root(nasl_file)
        base_dir = nasl_file.parent

        for match in matches:
            inc = match.group("value")
            # Check for include in root directory and
            # in the current nasl directory as in the original script.
            if not (root / inc).exists() and not (base_dir / inc).exists():
                yield LinterError(
                    f"The included file {inc} could not "
                    "be found within the VTs."
                )

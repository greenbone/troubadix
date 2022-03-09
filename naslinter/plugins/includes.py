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
from typing import Iterator, OrderedDict

from naslinter.helper import get_root
from naslinter.plugin import (
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
        *,
        tag_pattern: OrderedDict[str, re.Pattern],
        special_tag_pattern: OrderedDict[str, re.Pattern],
    ) -> Iterator[LinterResult]:
        """This script checks if the files used in include()
        exist on the local filesystem.
        An error will be thrown if a dependency could not be found.
        """
        del tag_pattern, special_tag_pattern

        # TODO: add to special_tag_pattern
        matches = re.compile(r'include\([\'"](?P<value>.+?)[\'"]\);').finditer(
            file_content
        )

        root = get_root(nasl_file)

        for match in matches:
            # Remove single and/or double quotes, spaces
            # and create a list by using the comma as a separator
            dependencies = re.sub(r'[\'"\s]', "", match.group("value")).split(
                ","
            )

            for dep in dependencies:
                if not (root / dep).exists():
                    yield LinterError(
                        f"The included file {dep} could not "
                        "be found within the VTs."
                    )

#  Copyright (c) 2022 Greenbone Networks GmbH
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
from typing import Iterator

from troubadix.plugin import FilePlugin, LinterError, LinterResult


class CheckTrailingSpacesTabs(FilePlugin):
    name = "check_trailing_spaces_tabs"

    def run(self) -> Iterator[LinterResult]:
        """This script checks if a VT is using one or more trailing whitespaces
         or tabs.

        Args:
            nasl_file: The VT that is going to be checked
            file_content: The content of the VT
            tag_pattern: A dictionary of regex patterns that are used to find
                    tags
            special_tag_pattern: A dictionary of regex patterns that are used
                    to find special tags

        """
        spaces_tabs_matches = re.finditer(
            r"[\t ]+$", self.context.file_content, flags=re.MULTILINE
        )

        if spaces_tabs_matches:
            for spaces_tabs_match in spaces_tabs_matches:
                if (
                    spaces_tabs_match is not None
                    and spaces_tabs_match.group(0) is not None
                ):
                    yield LinterError(
                        "The VT has one or more trailing spaces and/or tabs!",
                        file=self.context.nasl_file,
                        plugin=self.name,
                    )
                    return

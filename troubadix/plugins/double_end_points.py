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
from typing import Iterator

from troubadix.helper.patterns import get_common_tag_patterns
from troubadix.plugin import FilePlugin, LinterError, LinterResult


class CheckDoubleEndPoints(FilePlugin):
    name = "check_double_end_points"

    def run(
        self,
    ) -> Iterator[LinterResult]:
        """This script checks if a VT is using one or more doubled end point
        in a script_tag like e.g.:

            script_tag(name:"insight", value:"My insight..");

            or:

            script_tag(name:"insight", value:"My insight.
            .");
        """

        if self.context.nasl_file.suffix == ".inc":
            return

        tag_matches = get_common_tag_patterns().finditer(
            self.context.file_content
        )

        if tag_matches is not None:
            for tag_match in tag_matches:
                if tag_match:
                    doubled_end_points_match = re.search(
                        r'.*\.\s*\.(?P<quote>[\'"])\s*\)\s*;',
                        tag_match.group(0),
                        re.MULTILINE,
                    )
                    if doubled_end_points_match:

                        # Valid string used in a few VTs.
                        if (
                            'and much more...");'
                            in doubled_end_points_match.group(0)
                        ):
                            continue

                        yield LinterError(
                            f"The script tag '{tag_match.group('name')}' "
                            "is ending with two or more points: "
                            f"'{tag_match.group('value')}'.",
                            file=self.context.nasl_file,
                            plugin=self.name,
                        )

# Copyright (C) 2022 Greenbone AG
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
from typing import Iterator

from troubadix.helper.patterns import _get_special_script_tag_pattern
from troubadix.plugin import FilePlugin, LinterError, LinterResult

DEPENDENCY_ENTRY_PATTERN = re.compile(
    r'(?P<quote>[\'"])(?P<value>[^\'"]*)(?P=quote)'
)
WHITESPACE_PATTERN = re.compile(r"\s")


class CheckMalformedDependencies(FilePlugin):
    name = "check_malformed_dependencies"

    def run(
        self,
    ) -> Iterator[LinterResult]:
        """This script checks whether the files used in script_dependencies()
        exist on the local filesystem.
        An error will be thrown if a dependency could not be found.
        """

        if self.context.nasl_file.suffix == ".inc":
            return

        dependencies_pattern = _get_special_script_tag_pattern(
            "dependencies", flags=re.DOTALL | re.MULTILINE
        )

        file_content = self.context.file_content

        matches = dependencies_pattern.finditer(file_content)

        for match in matches:
            if not match:
                continue

            tag_value = (
                f'"{match.group("value")}"' if match.group("value") else ""
            )

            dependency_entries = DEPENDENCY_ENTRY_PATTERN.finditer(tag_value)

            for dependency_entry in dependency_entries:
                if not dependency_entry:
                    continue

                dependency_value = dependency_entry.group("value")

                if "," in dependency_value:
                    yield LinterError(
                        "The script dependency value is malformed and "
                        "contains a comma in the dependency value: "
                        f"'{dependency_value}'",
                        file=self.context.nasl_file,
                        plugin=self.name,
                    )

                if WHITESPACE_PATTERN.search(dependency_value):
                    yield LinterError(
                        "The script dependency value is malformed and "
                        "contains whitespace within the dependency value: "
                        f"'{dependency_value}'",
                        file=self.context.nasl_file,
                        plugin=self.name,
                    )

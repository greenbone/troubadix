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
from pathlib import Path
from typing import Iterator

from troubadix.helper.helper import FEED_VERSIONS, is_enterprise_folder
from troubadix.helper.patterns import _get_special_script_tag_pattern
from troubadix.plugin import (
    FilePlugin,
    LinterError,
    LinterResult,
    LinterWarning,
)


def split_dependencies(value: str) -> list[str]:
    """
    Remove single and/or double quotes, spaces
    and create a list by using the comma as a separator
    additionally, check and filter for inline comments
    """
    dependencies = []
    for line in value.splitlines():
        subject = line[: line.index("#")] if "#" in line else line
        _dependencies = re.sub(r'[\'"\s]', "", subject).split(",")
        dependencies += [dep for dep in _dependencies if dep != ""]
    return dependencies


class CheckDependencies(FilePlugin):
    name = "check_dependencies"

    def run(
        self,
    ) -> Iterator[LinterResult]:
        """This script checks whether the files used in script_dependencies()
        exist on the local filesystem.
        An error will be thrown if a dependency could not be found.
        """

        if self.context.nasl_file.suffix == ".inc":
            return

        file_content = self.context.file_content

        if "# troubadix: disable=template_nd_test_files_fps" in file_content:
            return

        dependencies_pattern = _get_special_script_tag_pattern(
            "dependencies", flags=re.DOTALL | re.MULTILINE
        )

        root = self.context.root

        matches = dependencies_pattern.finditer(file_content)

        for match in matches:
            if match:
                for dep in split_dependencies(match.group("value")):
                    if not any(
                        (root / vers / dep).exists() for vers in FEED_VERSIONS
                    ):
                        yield LinterError(
                            f"The script dependency {dep} could not "
                            "be found within the VTs.",
                            file=self.context.nasl_file,
                            plugin=self.name,
                        )
                        continue

                    dependency = Path(dep)
                    parts = dependency.parts

                    if is_enterprise_folder(parts[0]):
                        # strip parent enterprise folder
                        parts = parts[1:]

                    if len(parts) < 2:
                        # only the filename is contained in parts means
                        # no parent directory
                        continue

                    parent_folder = parts[0]
                    if parent_folder in ["Policy", "GSHB"]:
                        yield LinterWarning(
                            f"The script dependency {dep} is in a "
                            "subdirectory, which might be misplaced.",
                            file=self.context.nasl_file,
                            plugin=self.name,
                        )
                    else:
                        yield LinterError(
                            f"The script dependency {dep} is within "
                            "a subdirectory, which is not allowed.",
                            file=self.context.nasl_file,
                            plugin=self.name,
                        )

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

from troubadix.helper import SpecialScriptTag
from troubadix.helper.helper import is_enterprise_folder, FEED_VERSIONS
from troubadix.helper.patterns import get_special_script_tag_pattern
from troubadix.plugin import (
    FilePlugin,
    LinterError,
    LinterResult,
    LinterWarning,
)


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

        dependencies_pattern = get_special_script_tag_pattern(
            SpecialScriptTag.DEPENDENCIES
        )

        root = self.context.root
        file_content = self.context.file_content

        matches = dependencies_pattern.finditer(file_content)

        for match in matches:
            if match:
                # Remove single and/or double quotes, spaces
                # and create a list by using the comma as a separator
                dependencies = re.sub(
                    r'[\'"\s]', "", match.group("value")
                ).split(",")

                for dep in dependencies:
                    # TODO: gsf/PCIDSS/PCI-DSS.nasl,
                    # gsf/PCIDSS/v2.0/PCI-DSS-2.0.nasl
                    # and GSHB/EL15/GSHB.nasl
                    # are using a variable which we currently
                    # can't handle.
                    if "+d+.nasl" in dep:
                        continue

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
                    if parent_folder in ["PCIDSS", "Policy", "GSHB"]:
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

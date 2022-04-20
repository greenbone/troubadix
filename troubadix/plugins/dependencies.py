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

from typing import Iterator

from troubadix.helper import SpecialScriptTag
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
                    if not (root / dep).exists():
                        yield LinterError(
                            f"The script dependency {dep} could not "
                            "be found within the VTs."
                        )
                    else:
                        # TODO: gsf/PCIDSS/PCI-DSS.nasl,
                        # gsf/PCIDSS/v2.0/PCI-DSS-2.0.nasl
                        # and GSHB/EL15/GSHB.nasl
                        # are using a variable which we currently
                        # can't handle.
                        if "+d+.nasl" in dep:
                            continue

                        # Debug as those might be correctly placed
                        if dep[:4] == "gsf/" and not (
                            dep[:11] == "gsf/PCIDSS/"
                            or dep[:11] == "gsf/Policy/"
                        ):
                            yield LinterWarning(
                                f"The script dependency {dep} is in a "
                                "subdirectory, which might be misplaced."
                            )
                        # Subdirectories only allowed for directories
                        # on a whitelist
                        elif "/" in dep and not (
                            dep[:5] != "GSHB/"
                            or dep[:7] == "Policy/"
                            or dep[:11] == "gsf/PCIDSS/"
                            or dep[:11] == "gsf/Policy/"
                        ):
                            yield LinterWarning(
                                f"The script dependency {dep} is within "
                                "a subdirectory, which is not allowed."
                            )

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

from troubadix.helper import SpecialScriptTag, get_root
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class CheckDeprecatedDependency(FileContentPlugin):
    name = "check_deprecated_dependency"

    @staticmethod
    def run(
        nasl_file: Path,
        file_content: str,
        *,
        tag_pattern: OrderedDict[str, re.Pattern],
        special_tag_pattern: OrderedDict[str, re.Pattern],
    ) -> Iterator[LinterResult]:
        """No VT should depend on other VTs that are marked as deprecated via:

        script_tag(name:"deprecated", value:TRUE);
        exit(66);
        """
        del tag_pattern
        if not "script_dependencies(" in file_content:
            return

        root = get_root(nasl_file)

        matches = special_tag_pattern[
            SpecialScriptTag.DEPENDENCIES.value
        ].finditer(file_content)
        if not matches:
            return

        deprecated_pattern = re.compile(
            r"^\s*exit\s*\(\s*66\s*\)\s*;|script_tag\s*\(\s*name\s*:\s*[\"']"
            r"deprecated[\"']\s*,\s*value\s*:\s*TRUE\s*\)\s*;",
            re.MULTILINE,
        )
        deprecated = deprecated_pattern.search(file_content)
        if deprecated:
            return

        for match in matches:
            if match:
                # Remove single and/or double quotes, spaces
                # and create a list by using the comma as a separator
                dependencies = re.sub(
                    r'[\'"\s]', "", match.group("value")
                ).split(",")

                for dep in dependencies:
                    dependency_path = Path(root / dep)
                    if not dependency_path.exists():
                        yield LinterError(
                            f"The script dependency {dep} could not "
                            "be found within the VTs."
                        )
                    else:
                        # TODO: gsf/PCIDSS/PCI-DSS.nasl,
                        # gsf/PCIDSS/v2.0/PCI-DSS-2.0.nasl
                        # and GSHB/EL15/GSHB.nasl
                        # are using a variable which we currently can't handle.
                        if "+d+.nasl" in dep:
                            continue

                        dependency_content = dependency_path.read_text(
                            encoding="latin1"
                        )

                        dependency_deprecated = deprecated_pattern.search(
                            dependency_content
                        )
                        if dependency_deprecated:
                            yield LinterError(
                                f"VT depends on {dep}, which is marked"
                                "as deprecated."
                            )
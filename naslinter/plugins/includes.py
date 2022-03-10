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
    LinterWarning,
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
            else:
                # TODO: gsf/PCIDSS/PCI-DSS.nasl,
                # gsf/PCIDSS/v2.0/PCI-DSS-2.0.nasl
                # and GSHB/EL15/GSHB.nasl
                # are using a variable which we currently
                # can't handle.
                if "+d+.nasl" in inc:
                    continue

                # Debug as those might be correctly placed
                if inc[:4] == "gsf/" and not (
                    inc[:11] == "gsf/PCIDSS/" or inc[:11] == "gsf/Policy/"
                ):
                    yield LinterWarning(
                        f"The included file {inc} is in a "
                        "subdirectory, which might be misplaced."
                    )
                # Subdirectories only allowed for directories
                # on a whitelist
                elif "/" in inc and not (
                    inc[:5] != "GSHB/"
                    or inc[:7] == "Policy/"
                    or inc[:11] == "gsf/PCIDSS/"
                    or inc[:11] == "gsf/Policy/"
                    or inc[:4] == "gcf/"
                    or inc[:9] == "nmap_nse/"
                ):
                    yield LinterWarning(
                        f"The included file {inc} is within "
                        "a subdirectory, which is not allowed."
                    )

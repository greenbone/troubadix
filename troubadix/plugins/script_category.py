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
from pathlib import Path
from typing import Iterator, OrderedDict

from troubadix.plugin import FileContentPlugin, LinterError, LinterResult

SCRIPT_CATEGORIES = {
    "ACT_INIT": 0,
    "ACT_SCANNER": 1,
    "ACT_SETTINGS": 2,
    "ACT_GATHER_INFO": 3,
    "ACT_ATTACK": 4,
    "ACT_MIXED_ATTACK": 5,
    "ACT_DESTRUCTIVE_ATTACK": 6,
    "ACT_DENIAL": 7,
    "ACT_KILL_HOST": 8,
    "ACT_FLOOD": 9,
    "ACT_END": 10,
}


class CheckScriptCategory(FileContentPlugin):
    name = "check_script_category"

    @staticmethod
    def run(
        nasl_file: Path,
        file_content: str,
        *,
        tag_pattern: OrderedDict[str, re.Pattern],
        special_tag_pattern: OrderedDict[str, re.Pattern],
    ) -> Iterator[LinterResult]:
        del tag_pattern, special_tag_pattern
        if nasl_file.suffix == ".inc":
            return

        own_category_match = re.search(
            r"^\s*script_category\s*\(([^)]{3,})\)\s*;",
            file_content,
            re.MULTILINE,
        )

        if own_category_match is None or own_category_match.group(1) is None:
            yield LinterError("VT is missing a script_category.")
            return

        # pylint: disable=line-too-long
        # See https://github.com/greenbone/openvas-scanner/blob/master/misc/nvt_categories.h
        # for a list of the category numbers.
        own_category = own_category_match.group(1)
        if own_category not in SCRIPT_CATEGORIES:
            yield LinterError(
                f"VT is using an unsupported category '{own_category}'."
            )
            return

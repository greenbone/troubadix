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

from troubadix.helper.patterns import ScriptTag, SpecialScriptTag
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class CheckDuplicatedScriptTags(FileContentPlugin):
    name = "check_duplicated_script_tags"

    @staticmethod
    def run(
        nasl_file: Path,
        file_content: str,
        *,
        tag_pattern: OrderedDict[str, re.Pattern],
        special_tag_pattern: OrderedDict[str, re.Pattern],
    ) -> Iterator[LinterResult]:
        for tag in SpecialScriptTag:
            # TBD: script_name might also look like this:
            # script_name("MyVT (Windows)");
            match = special_tag_pattern[tag.value].finditer(file_content)

            if match:
                # This is allowed, see e.g.
                # gb_netapp_data_ontap_consolidation.nasl
                if tag.value == "dependencies" and "FEED_NAME" in file_content:
                    continue
                if tag.value == "xref":
                    continue
                match = list(match)
                if len(match) > 1:
                    yield LinterError(
                        f"The VT is using the script tag 'script_"
                        f"{tag.value}' multiple number of times."
                    )

        for tag in ScriptTag:
            match = tag_pattern[tag.value].finditer(file_content)

            if match:
                match = list(match)
                if len(match) > 1:
                    yield LinterError(
                        f"The VT is using the script tag '{tag.value}' "
                        "multiple number of times."
                    )

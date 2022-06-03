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

from typing import Iterator

from troubadix.helper.patterns import (
    get_script_tag_patterns,
    get_special_script_tag_patterns,
)
from troubadix.plugin import FilePlugin, LinterError, LinterResult


allowed_dup_dependencies = [
    "GSHB/EL15/GSHB.nasl",
    "gsf/PCIDSS/PCI-DSS.nasl",
    "gsf/PCIDSS/v2.0/PCI-DSS-2.0.nasl",
]


class CheckDuplicatedScriptTags(FilePlugin):
    name = "check_duplicated_script_tags"

    def run(self) -> Iterator[LinterResult]:

        if self.context.nasl_file.suffix == ".inc":
            return

        special_script_tag_patterns = get_special_script_tag_patterns()
        file_content = self.context.file_content
        for tag, pattern in special_script_tag_patterns.items():
            # TBD: script_name might also look like this:
            # script_name("MyVT (Windows)");

            if tag.name == "ADD_PREFERENCE":
                continue

            if tag.name == "DEPENDENCIES":
                file_path = str(self.context.nasl_file)
                if any(f in file_path for f in allowed_dup_dependencies):
                    continue

            match = pattern.finditer(file_content)

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
                        f"{tag.value}' multiple number of times.",
                        file=self.context.nasl_file,
                        plugin=self.name,
                    )

        script_tag_patterns = get_script_tag_patterns()
        for tag, pattern in script_tag_patterns.items():
            match = pattern.finditer(file_content)

            if match:
                match = list(match)
                if len(match) > 1:
                    yield LinterError(
                        f"The VT is using the script tag '{tag.value}' "
                        "multiple number of times.",
                        file=self.context.nasl_file,
                        plugin=self.name,
                    )

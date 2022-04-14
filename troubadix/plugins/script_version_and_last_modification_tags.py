#  Copyright (c) 2022 Greenbone Networks GmbH
#
#  SPDX-License-Identifier: GPL-3.0-or-later
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

from pathlib import Path
from typing import Iterator

from troubadix.helper.patterns import (
    ScriptTag,
    SpecialScriptTag,
    get_script_tag_pattern,
    get_special_script_tag_pattern,
)
from troubadix.plugin import LinterError, FileContentPlugin, LinterResult


class CheckScriptVersionAndLastModificationTags(FileContentPlugin):
    name = "check_script_version_and_last_modification_tags"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """The script checks if the passed VT has a correct syntax of the
        following two tags:

        - script_version();
        - script_tag(name:"last_modification", value:"");

        An error will be thrown if the syntax of those two tags does not match
        the requirements.

        Args:
            nasl_file: The VT that shall be checked
            file_content: The content of the VT that shall be checked
        """
        # script_version("2019-03-21T12:19:01+0000");")
        version_pattern = get_special_script_tag_pattern(
            SpecialScriptTag.VERSION
        )
        match_ver_modified = version_pattern.search(file_content)

        if not match_ver_modified:
            yield LinterError(
                f"VT '{str(nasl_file)}' is missing "
                "script_version(); or "
                "is using a wrong syntax.\n"
            )

        # script_tag(name:"last_modification",
        # value:"2019-03-21 12:19:01 +0000 (Thu, 21 Mar 2019)");
        last_modification_pattern = get_script_tag_pattern(
            ScriptTag.LAST_MODIFICATION
        )
        match_last_modified = last_modification_pattern.search(file_content)

        if not match_last_modified:
            yield LinterError(
                f"VT '{str(nasl_file)}' is missing script_tag("
                'name:"last_modification" or is using a wrong '
                "syntax.\n"
            )

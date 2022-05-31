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

import re
from pathlib import Path
from typing import Iterator

from troubadix.helper.patterns import (
    ScriptTag,
    SpecialScriptTag,
    get_script_tag_pattern,
    get_special_script_tag_pattern,
)
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


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
        if nasl_file.suffix == ".inc":
            return

        # script_version("2019-03-21T12:19:01+0000");")
        version_pattern = get_special_script_tag_pattern(
            SpecialScriptTag.VERSION
        )
        version_match = version_pattern.search(file_content)

        if not version_match:
            revision_pattern = re.compile(
                r'script_(?P<name>version)\s*\((?P<quote99>[\'"])?(?P<value>\$'
                r"Revision:\s*[0-9]{1,6}\s* \$)(?P=quote99)?\s*\)\s*;"
            )
            revision_match = revision_pattern.search(file_content)
            if not revision_match:
                yield LinterError(
                    "VT is missing script_version(); or is using a wrong "
                    "syntax.",
                    file=nasl_file,
                    plugin=self.name,
                )

        # script_tag(name:"last_modification",
        # value:"2019-03-21 12:19:01 +0000 (Thu, 21 Mar 2019)");
        last_modification_pattern = get_script_tag_pattern(
            ScriptTag.LAST_MODIFICATION
        )
        match_last_modified = last_modification_pattern.search(file_content)

        if not match_last_modified:
            old_pattern = re.compile(
                r'script_tag\(\s*name\s*:\s*(?P<quote>[\'"])(?P<name>'
                r"last_modification)(?P=quote)\s*,\s*value\s*:\s*(?P<quote2>"
                r'[\'"])?(?P<value>\$Date:\s*[A-Za-z0-9\:\-\+\,\s\(\)]{44}'
                r"\s*\$)(?P=quote2)?\s*\)\s*;"
            )
            match_last_modified = old_pattern.search(file_content)
            if not match_last_modified:
                yield LinterError(
                    "VT is missing script_tag("
                    'name:"last_modification" or is using a wrong '
                    "syntax.",
                    file=nasl_file,
                    plugin=self.name,
                )

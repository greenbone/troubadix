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

import datetime
import re
from pathlib import Path
from typing import Iterator

from troubadix.helper import CURRENT_ENCODING
from troubadix.helper.patterns import (
    LAST_MODIFICATION_ANY_VALUE_PATTERN,
    SCRIPT_VERSION_ANY_VALUE_PATTERN,
    ScriptTag,
    SpecialScriptTag,
    get_script_tag_pattern,
    get_special_script_tag_pattern,
)
from troubadix.plugin import (
    FileContentPlugin,
    LinterError,
    LinterFix,
    LinterResult,
)


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
        self.fix_last_modification_and_version = False

        if nasl_file.suffix == ".inc":
            return

        match_script_version_any = re.search(
            pattern=SCRIPT_VERSION_ANY_VALUE_PATTERN,
            string=file_content,
        )
        if not match_script_version_any:
            yield LinterError(
                "VT is missing script_version();.",
                file=self.context.nasl_file,
                plugin=self.name,
            )
            return

        self.old_script_version = match_script_version_any.group(0)
        self.old_script_version_value = match_script_version_any.group("value")

        # script_version("2019-03-21T12:19:01+0000");")
        version_pattern = get_special_script_tag_pattern(
            SpecialScriptTag.VERSION
        )
        version_match = version_pattern.search(file_content)

        if not version_match:
            # check for old format:
            # script_version("$Revision: 12345 $");
            revision_pattern = re.compile(
                r'script_(?P<name>version)\s*\((?P<quote99>[\'"])?(?P<value>\$'
                r"Revision:\s*[0-9]{1,6}\s* \$)(?P=quote99)?\s*\)\s*;"
            )
            revision_match = revision_pattern.search(file_content)
            if not revision_match:
                self.fix_last_modification_and_version = True
                yield LinterError(
                    "VT is using a wrong script_version(); syntax.",
                    file=nasl_file,
                    plugin=self.name,
                )

        match_last_modification_any_value = re.search(
            pattern=LAST_MODIFICATION_ANY_VALUE_PATTERN,
            string=file_content,
        )

        if not match_last_modification_any_value:
            self.fix_last_modification_and_version = False
            yield LinterError(
                'VT is missing script_tag(name:"last_modification".',
                file=self.context.nasl_file,
                plugin=self.name,
            )
            return

        self.old_last_modification = match_last_modification_any_value.group(0)
        self.old_last_modification_value = (
            match_last_modification_any_value.group("value")
        )

        # script_tag(name:"last_modification",
        # value:"2019-03-21 12:19:01 +0000 (Thu, 21 Mar 2019)");
        last_modification_pattern = get_script_tag_pattern(
            ScriptTag.LAST_MODIFICATION
        )
        match_last_modified = last_modification_pattern.search(file_content)

        if not match_last_modified:
            # check for old format:
            # script_tag(name: "last_modification",
            #   value: "$Date: 2021-07-19 12:32:02 +0000 (Mon, 19 Jul 2021) $")
            old_pattern = re.compile(
                r'script_tag\(\s*name\s*:\s*(?P<quote>[\'"])(?P<name>'
                r"last_modification)(?P=quote)\s*,\s*value\s*:\s*(?P<quote2>"
                r'[\'"])?(?P<value>\$Date:\s*[A-Za-z0-9\:\-\+\,\s\(\)]{44}'
                r"\s*\$)(?P=quote2)?\s*\)\s*;"
            )
            match_last_modified = old_pattern.search(file_content)
            if not match_last_modified:
                self.fix_last_modification_and_version = True
                yield LinterError(
                    "VT is is using a wrong syntax for script_tag("
                    'name:"last_modification".',
                    file=nasl_file,
                    plugin=self.name,
                )

    def fix(self) -> Iterator[LinterResult]:
        if not self.fix_last_modification_and_version:
            return

        tag_template = 'script_tag(name:"last_modification", value:"{date}");'
        version_template = 'script_version("{date}");'

        now = datetime.datetime.now(datetime.timezone.utc)

        file_content = self.context.file_content

        # get that version date formatted correctly:
        # "2021-03-24T10:08:26+0000"
        correctly_formatted_version = f"{now:%Y-%m-%dT%H:%M:%S%z}"

        file_content = file_content.replace(
            self.old_script_version,
            version_template.format(date=correctly_formatted_version),
        )

        # get that last modification date formatted correctly:
        # "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)"
        correctly_formatted_last_modification = (
            f"{now:%Y-%m-%d %H:%M:%S %z (%a, %d %b %Y)}"
        )

        file_content = file_content.replace(
            self.old_last_modification,
            tag_template.format(date=correctly_formatted_last_modification),
        )

        self.context.nasl_file.write_text(
            file_content, encoding=CURRENT_ENCODING
        )

        yield LinterFix(
            f"Replaced last_modification {self.old_last_modification_value} "
            f"with {correctly_formatted_last_modification} and script_version "
            f"{self.old_script_version_value} with "
            f"{correctly_formatted_version}.",
            file=self.context.nasl_file,
            plugin=self.name,
        )

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

from troubadix.helper import subprocess_cmd
from troubadix.plugin import LinterError, FileContentPlugin, LinterResult


class CheckUpdatedDateVersion(FileContentPlugin):
    name = "check_updated_date_version"

    @staticmethod
    def run(
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """The script checks (via git diff) if the passed VT has changed both
        of the following two tags via the replace_svn_props.py script:

        - script_version();
        - script_tag(name:"last_modification", value:"");

        An error will be thrown if one or both tags where unchanged.

        Args:
            nasl_file: The VT that shall be checked
            file_content: The content of the file
            tag_pattern: The pattern for the tag
            special_tag_pattern: The pattern for the special tag

        """
        text, _ = subprocess_cmd(
            "git -c color.status=false --no-pager diff --cached "
            f"{str(nasl_file)}"
        )

        # if changed the following two examples needs to be in the git output:
        #
        # +  script_version("2019-03-21T12:19:01+0000");
        #
        # +  script_tag(name:"last_modification", value:"2019-03-21 12:19:01 +0000 (Thu, 21 Mar 2019)"); #pylint: disable=line-too-long
        match_ver_modified = re.search(
            r'^\+\s*script_version\("[0-9\-\:\+T]{24}"\);',
            text,
            re.MULTILINE,
        )
        if match_ver_modified is None:
            yield LinterError(
                "Changed VT has a not updated script_version();\n"
                "Please run ./replace_svn_props.py to update both tags.\n"
            )

        match_last_modified = re.search(
            r'^\+\s*script_tag\(name:"last_modification",\svalue:"['
            r'A-Za-z0-9\:\-\+\,\s\(\)]{44}"\);',
            text,
            re.MULTILINE,
        )
        if match_last_modified is None:
            yield LinterError(
                "Changed VT has a not updated script_tag("
                'name:"last_modification", ...);\n'
                "Please run ./replace_svn_props.py to update both tags.\n"
            )

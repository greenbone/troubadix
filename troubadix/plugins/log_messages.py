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
from typing import Iterator, OrderedDict

from troubadix.helper import ScriptTag
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class CheckLogMessages(FileContentPlugin):
    name = "check_log_messages"

    @staticmethod
    def run(
        nasl_file: Path,
        file_content: str,
        *,
        tag_pattern: OrderedDict[str, re.Pattern],
        special_tag_pattern: OrderedDict[str, re.Pattern],
    ) -> Iterator[LinterResult]:
        """This script checks the passed VT if it is using a log_message and
            having a severity (CVSS score) assigned which is an error /
            debugging leftover in most cases.

        Args:
            nasl_file: The VT that is going to be checked
            file_content: The content of the VT

        """
        del special_tag_pattern

        log_match = re.search(
            r"log_message\s*\([\s\n]*\)\s*(;|;\s*(\n|#))",
            file_content,
            re.MULTILINE,
        )
        if log_match:
            yield LinterError("The VT is using an empty log_message() function")

        if nasl_file.suffix == ".inc":
            return
        # Policy VTs might use both, security_message and log_message
        if "Policy/" in str(nasl_file):
            return

        # don't need to check detection scripts since they are for sure using
        # a log_message. all detection scripts have a cvss of 0.0
        cvss_detect = tag_pattern[ScriptTag.CVSS_BASE.value].search(
            file_content
        )

        if cvss_detect and cvss_detect.group("value") == "0.0":
            return

        # jf: Bugfix for https://jira.greenbone.net/browse/FE-1004 ?!
        # log_match = re.search(r'.*(log_message[\s]*\([^)]+\)[\s]*;)',
        #                       file_content, re.MULTILINE)
        log_match = re.search(
            r"log_message\s*\([\w:#\.&\-!,<>\[\]("
            r")\s\"+\'/\\\n]+\)\s*(;|;\s*(\n|#))",
            file_content,
            re.MULTILINE,
        )
        if log_match:
            yield LinterError(
                "The VT is using a log_message in a VT with a severity"
            )
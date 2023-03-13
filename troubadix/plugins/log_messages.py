#  Copyright (c) 2022 Greenbone AG
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

from troubadix.helper import ScriptTag
from troubadix.helper.patterns import get_script_tag_pattern
from troubadix.plugin import (
    FileContentPlugin,
    LinterError,
    LinterResult,
    LinterWarning,
)


class CheckLogMessages(FileContentPlugin):
    name = "check_log_messages"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """This script checks the passed VT if it is using a log_message and
            having a severity (CVSS score) assigned which is an error /
            debugging leftover in most cases.

        Args:
            nasl_file: The VT that is going to be checked
            file_content: The content of the VT

        """
        log_match = re.search(
            r"log_message\s*\([\s\n]*\)\s*(;|;\s*(\n|#))",
            file_content,
            re.MULTILINE,
        )
        if log_match:
            yield LinterError(
                "The VT is using an empty log_message() function",
                file=nasl_file,
                plugin=self.name,
            )

        if nasl_file.suffix == ".inc":
            return

        # Policy VTs might use both, security_message and log_message
        if "Policy/" in str(nasl_file):
            return

        # don't need to check detection scripts since they are for sure using
        # a log_message. all detection scripts have a cvss of 0.0
        cvss_pattern = get_script_tag_pattern(ScriptTag.CVSS_BASE)
        cvss_detect = cvss_pattern.search(file_content)

        if cvss_detect and cvss_detect.group("value") == "0.0":
            return

        # log_match = re.search(r'.*(log_message[\s]*\([^)]+\)[\s]*;)',
        #                       file_content, re.MULTILINE)
        log_match = re.search(
            r"log_message\s*\([\w:#\.&\-!,<>\[\]("
            r")\s\"+\'/\\\n]+\)\s*(;|;\s*(\n|#))",
            file_content,
            re.MULTILINE,
        )
        if log_match:
            yield LinterWarning(
                "The VT is using a log_message in a VT with a severity",
                file=nasl_file,
                plugin=self.name,
            )

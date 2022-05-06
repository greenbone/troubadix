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

from troubadix.helper.patterns import ScriptTag, get_script_tag_pattern
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class CheckSecurityMessages(FileContentPlugin):
    name = "check_security_messages"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """This script checks the passed VT if it is using a security_message
        and having no severity (CVSS score) assigned which is an error /
        debugging leftover in most cases.

        Args:
            nasl_file: The VT that is going to be checked
            file_content: The content of the VT

        """
        if nasl_file.suffix == ".inc":
            return

        # Policy VTs might use both, security_message and log_message
        if (
            "Policy/" in str(nasl_file)
            or "PCIDSS/" in str(nasl_file)
            or "GSHB/" in str(nasl_file)
        ):
            return

        # don't need to check VTs having a severity (which are for sure
        # using a security_message) or no cvss_base (which shouldn't happen and
        # is checked in a separate step) included at all.
        cvss_base_pattern = get_script_tag_pattern(ScriptTag.CVSS_BASE)
        cvss_detect = cvss_base_pattern.search(file_content)

        if cvss_detect and cvss_detect.group("value") != "0.0":
            return

        sec_match = re.search(
            r"security_message\s*\([\w:#.&\-!,<>\[\]("
            r")\s\"`+'/\\\n]+\)\s*(;|;\s*(\n|#))",
            file_content,
            re.MULTILINE,
        )

        if sec_match:
            yield LinterError(
                "VT is using a security_message in a VT without severity",
                file=nasl_file,
                plugin=self.name,
            )

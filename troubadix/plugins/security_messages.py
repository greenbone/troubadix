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

from troubadix.helper.patterns import ScriptTag
from troubadix.plugin import LinterError, FileContentPlugin, LinterResult


class CheckSecurityMessages(FileContentPlugin):
    name = "check_security_messages"

    @staticmethod
    def run(
        nasl_file: Path,
        file_content: str,
        *,
        tag_pattern: OrderedDict[str, re.Pattern],
        special_tag_pattern: OrderedDict[str, re.Pattern],
    ) -> Iterator[LinterResult]:
        """This script checks the passed VT if it is using a security_message
        and having no severity (CVSS score) assigned which is an error /
        debugging leftover in most cases.

        Args:
            nasl_file: The VT that is going to be checked
            file_content: The content of the VT

        """
        del special_tag_pattern
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
        cvss_detect = tag_pattern[ScriptTag.CVSS_BASE.value].search(
            file_content
        )

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
                "VT is using a security_message in a VT without severity"
            )
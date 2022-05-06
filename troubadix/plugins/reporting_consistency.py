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
from typing import Iterator

from troubadix.helper.patterns import ScriptTag, get_script_tag_pattern
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class CheckReportingConsistency(FileContentPlugin):
    name = "check_reporting_consistency"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """This script checks the consistency between log_message,
        security_message reporting function and
        the cvss base value.
        """
        if nasl_file.suffix == ".inc":
            return

        security_message = re.compile(
            r"^\s*[^#]?\s*security_message\s*\(.+?\)\s*;\s",
            re.MULTILINE | re.DOTALL,
        ).search(file_content)
        log_message = re.compile(
            r"^\s*[^#]?\s*log_message\s*\(.+?\)\s*;\s",
            re.MULTILINE | re.DOTALL,
        ).search(file_content)

        cvss_base_pattern = get_script_tag_pattern(ScriptTag.CVSS_BASE)
        cvss_base = cvss_base_pattern.search(file_content)

        if not cvss_base:
            yield LinterError(
                "VT/Include has no cvss_base tag",
                file=nasl_file,
                plugin=self.name,
            )
            return

        if log_message and cvss_base.group("value") != "0.0":
            yield LinterError(
                "Tag cvss_base is not 0.0 use report function security_message",
                file=nasl_file,
                plugin=self.name,
            )

        if security_message and cvss_base.group("value") == "0.0":
            yield LinterError(
                "Tag cvss_base is 0.0 use report function log_message",
                file=nasl_file,
                plugin=self.name,
            )

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
from typing import Iterator, OrderedDict

from troubadix.helper.patterns import ScriptTag
from troubadix.plugin import LinterError, FileContentPlugin, LinterResult


class CheckReportingConsistency(FileContentPlugin):
    name = "check_reporting_consistency"

    @staticmethod
    def run(
        nasl_file: Path,
        file_content: str,
        *,
        tag_pattern: OrderedDict[str, re.Pattern],
        special_tag_pattern: OrderedDict[str, re.Pattern],
    ) -> Iterator[LinterResult]:
        """This script checks the consistency between log_message,
        security_message reporting function and
        the cvss base value.
        """
        del special_tag_pattern

        if nasl_file.suffix == ".inc":
            return

        report_function = re.compile(r"log_message|security_message").search(
            file_content
        )
        if not report_function:
            # We can't do anything about this one, skipping
            return

        cvss_base = tag_pattern[ScriptTag.CVSS_BASE.value].search(file_content)

        if not cvss_base:
            yield LinterError("VT/Include has no cvss_base tag")
            return

        if (
            report_function.group() == "log_message"
            and cvss_base.group("value") != "0.0"
        ):
            yield LinterError(
                "Tag cvss_base is not 0.0 use report function security_message"
            )

        if (
            report_function.group() == "security_message"
            and cvss_base.group("value") == "0.0"
        ):
            yield LinterError(
                "Tag cvss_base is 0.0 use report function log_message"
            )
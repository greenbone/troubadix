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
from datetime import datetime
from pathlib import Path
from typing import Iterator

from troubadix.helper import ScriptTag, get_script_tag_pattern
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class CheckCVEFormat(FileContentPlugin):
    name = "check_cve_format"

    @staticmethod
    def run(
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        if nasl_file.suffix == ".inc":
            return

        tag_pattern = get_script_tag_pattern(ScriptTag.CVSS_BASE)

        # don't need to check detection scripts since they don't refer to CVEs.
        # all detection scripts have a cvss of 0.0
        cvss_detect = tag_pattern.search(file_content)
        # cvss_detect = re.search(
        #     r'script_tag\s*\(name\s*:\s*"cvss_base",'
        #     r'\s*value:\s*"(\d{1,2}\.\d)"',
        #     file_content,
        # )
        if cvss_detect and cvss_detect.group("value") == "0.0":
            return

        # ("CVE-2017-2750");
        match_result = re.search("(?<=script_cve_id)[^;]+", file_content)
        if match_result is None or match_result.group(0) is None:
            yield LinterError("VT does not refer to any CVEs.")
            return

        found_cves = []
        matches = match_result.group(0).split(",")
        current_year = datetime.now().year
        for match in matches:
            result = re.search(r'"CVE-\d{4}-\d{4,7}"', match)
            if result is None or result.group(0) is None:
                yield LinterError("VT uses an invalid CVE format.")
                return

            cve = result.group(0)

            if len(cve) > 15 and cve[10] == "0":
                yield LinterError(
                    "The last group of CVE digits of the VT "
                    "must not start with a 0 if there are more than 4 digits."
                )

            year = cve.split("-")
            if not 1999 <= int(year[1]) <= current_year:
                yield LinterError("VT uses an invalid year in CVE format.")

            if cve in found_cves:
                yield LinterError(f"VT is using CVE {cve} multiple times.")

            found_cves.append(cve)

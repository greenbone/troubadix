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

from naslinter.plugin import LinterError, FileContentPlugin, LinterResult

SIMPLE_CALLS_TO_CHECK = [
    "mandatory_keys",
    "name",
    "require_keys",
    "exclude_keys",
    "oid",
    "require_ports",
    "require_udp_ports",
    "copyright",
    "family",
    "category",
    "cve_id",
    "version",
    "bugtraq_id",
    "dependencies",
]
SCRIPT_TAGS_TO_CHECK = [
    "solution",
    "solution_type",
    "qod_type",
    "cvss_base",
    "cvss_base_vector",
    "summary",
    "last_modification",
    "insight",
    "affected",
    "creation_date",
    "vuldetect",
    "impact",
    "deprecated",
    "qod",
    "severity_vector",
    "severity_origin",
    "severity_date",
]


class CheckDuplicatedScriptTags(FileContentPlugin):
    name = "check_duplicated_script_tags"

    @staticmethod
    def run(nasl_file: Path, file_content: str) -> Iterator[LinterResult]:
        for check in SIMPLE_CALLS_TO_CHECK:
            # TBD: script_name might also look like this:
            # script_name("MyVT (Windows)");
            match = re.findall(
                r"^ *script_" + check + r" *\([^)]+\) *;",
                file_content,
                re.MULTILINE,
            )
            if match and len(match) > 1:
                # This is allowed, see e.g.
                # gb_netapp_data_ontap_consolidation.nasl
                if check == "dependencies" and "FEED_NAME" in file_content:
                    continue

                function = match[0].partition("(")[0]
                yield LinterError(
                    f"The VT is using the script function "
                    f"'{function}' multiple number of times."
                )

        for check in SCRIPT_TAGS_TO_CHECK:
            match = re.findall(
                r"^ *script_tag *\( *name *: *[\"']"
                + check
                + r"[\"'] *, *value *: *.*?(?=\) *;)+\) *;",
                file_content,
                re.MULTILINE | re.DOTALL,
            )
            if match and len(match) > 1:
                tag = match[0].partition(",")[0]
                yield LinterError(
                    f"The VT is using the script tag '{tag}' "
                    "multiple number of times."
                )

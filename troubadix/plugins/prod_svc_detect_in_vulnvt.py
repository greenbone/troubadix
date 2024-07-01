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
from typing import Iterator

from troubadix.helper import is_ignore_file, ScriptTag, SpecialScriptTag
from troubadix.helper.patterns import (
    _get_special_script_tag_pattern,
    get_script_tag_pattern,
)
from troubadix.plugin import FilePlugin, LinterError, LinterResult

IGNORE_FILES = []


class CheckProdSvcDetectInVulnvt(FilePlugin):
    name = "check_prod_svc_detect_in_vulnvt"

    def run(self) -> Iterator[LinterResult]:
        """This script checks if the passed VT is doing a vulnerability
        reporting and a product / service detection together in a single VT.
        More specific this step is checking and reporting VTs having a severity
        but are placed in these Families:

        - script_family("Product detection");
        - script_family("Service detection");

        and / or are using one of the following functions:

        - register_product()
        - register_and_report_os()
        - register_and_report_cpe()
        - register_host_detail()
        - service_register()
        - service_report()
        - build_cpe()
        - build_detection_report()
        - report_host_detail_single()
        - report_host_details()
        - report_best_os_cpe()
        - report_best_os_txt()

        Args:
            nasl_file: The VT that is going to be checked
            file_content: The content of the VT
        """
        if self.context.nasl_file.suffix == ".inc" or is_ignore_file(
            self.context.nasl_file, IGNORE_FILES
        ):
            return

        file_content = self.context.file_content
        # Don't need to check VTs having a cvss of 0.0
        cvss_base_pattern = get_script_tag_pattern(ScriptTag.CVSS_BASE)
        cvss_detect = cvss_base_pattern.search(file_content)

        if cvss_detect is not None and cvss_detect.group("value") == "0.0":
            return

        match_family = _get_special_script_tag_pattern(
            name=SpecialScriptTag.FAMILY.value,
            value=r"(Product|Service) detection",
        ).search(file_content)
        if match_family and match_family.group("value"):
            yield LinterError(
                "VT has a severity but is placed in the family '"
                f"{match_family.group('value')}' which is not allowed for this "
                "VT. Please split this VT into a separate Product/Service "
                "detection and Vulnerability-VT.",
                file=self.context.nasl_file,
                plugin=self.name,
            )

        matches = re.finditer(
            r"(?P<function>("
            r"register_(product|and_report_(os|cpe)|host_detail)|"
            r"service_(register|report)|"
            r"build_(cpe|detection_report)|"
            r"report_(host_(detail_single|details)|best_os_(cpe|txt)))"
            r")\s*\((?P<body>[^)]+)\)\s*;",
            file_content,
            re.MULTILINE,
        )
        if matches:
            for match in matches:
                if all(
                    det not in match.group("body")
                    for det in ["detected_by", "detected_at"]
                ):
                    yield LinterError(
                        "VT has a severity but is using the function '"
                        f"{match.group('function')}' which is not allowed for "
                        "this VT. Please split this VT into a separate "
                        "Product/Service detection and Vulnerability-VT.",
                        file=self.context.nasl_file,
                        plugin=self.name,
                    )

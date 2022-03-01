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

from naslinter.helper import (
    get_tag_pattern,
    get_special_tag_pattern,
    SpecialScriptTag,
)
from naslinter.plugin import LinterError, FileContentPlugin, LinterResult


class CheckProdSvcDetectInVulnvt(FileContentPlugin):
    name = "check_prod_svc_detect_in_vulnvt"

    @staticmethod
    def run(nasl_file: Path, file_content: str) -> Iterator[LinterResult]:
        """This script checks if the passed VT if it is doing a vulnerability
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

        # Don't need to check VTs having a cvss of 0.0
        cvss_detect = get_tag_pattern(
            name="cvss_base", value=r'"(?P<score>\d{1,2}\.\d)"'
        ).search(file_content)

        if cvss_detect is not None and cvss_detect.group("score") == "0.0":
            return

        match_family = get_special_tag_pattern(
            name=SpecialScriptTag.FAMILY,
            value=r'\s*"(?P<family>(Product|Service) detection)"\s*',
        ).search(file_content)
        if match_family and match_family.group("family"):
            yield LinterError(
                f"VT '{str(nasl_file)}' has a severity but is "
                "placed in the following family which is "
                "disallowed for such a "
                f"VT:\n\n{match_family.group(0)}\n\n"
                "Please split this VT into a separate Product / "
                "Service detection and Vulnerability-VT.\n"
            )

        match_funcs = re.finditer(
            r"(register_(product|and_report(os|cpe)|host_detail)|service_("
            r"register|report)|build_(cpe|detection_report)|"
            r"report_(host_(detail_single|details)|best_os_(cpe|txt)))"
            r"\s*\([^)]*\)\s*;",
            file_content,
            re.MULTILINE,
        )
        if match_funcs:
            for match_func in match_funcs:
                if "detected_by" not in match_func.group(
                    0
                ) and "detected_at" not in match_func.group(0):
                    yield LinterError(
                        f"VT '{str(nasl_file)}' has a severity but is "
                        "using the following functions which is "
                        "disallowed for such a VT:\n\n"
                        f"{match_func.group(0)}\n\nPlease split this "
                        "VT into a separate Product / Service detection and "
                        "Vulnerability-VT.\n"
                    )

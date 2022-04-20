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

from itertools import chain
from typing import AnyStr, Iterator

from troubadix.helper import (
    SpecialScriptTag,
    get_common_tag_patterns,
)
from troubadix.helper.patterns import get_special_script_tag_pattern
from troubadix.plugin import LinterError, LinterResult, FilePlugin


class CheckHttpLinksInTags(FilePlugin):
    name = "check_http_links_in_tags"

    def run(self) -> Iterator[LinterResult]:
        return chain(
            self.contains_http_link_in_tag(),
            self.contains_nvd_mitre_link_in_xref(),
        )

    def contains_http_link_in_tag(self) -> Iterator[LinterResult]:
        """Checks a given file if any of the
        script_tag(name:"(summary|impact|affected|insight|vuldetect|
        solution)", value:"")
        contains a http(s)://, ftp:(s)://, ftp. and/or www. link which
        should be moved to the following tag instead:

        script_xref(name:"URL", value:"");

        Args:
                nasl_file: The VT that is going to be checked
                file_content: The content of the file that is going to be
                            checked
        """

        file_content = self.context.file_content
        pattern = get_common_tag_patterns()
        tag_matches: Iterator[re.Match] = pattern.finditer(file_content)

        for tag_match in tag_matches:
            if tag_match:
                http_link_matches = re.finditer(
                    r".*((http|ftp)s?://|(www|\s+ftp)\.).*",
                    tag_match.group("value"),
                )
                if http_link_matches:
                    for http_link_match in http_link_matches:
                        if http_link_match:
                            if self.check_to_continue(http_link_match.group(0)):
                                continue

                            yield LinterError(
                                "One script_tag in the VT is using a HTTP "
                                "link/URL which should be moved to a separate "
                                '\'script_xref(name:"URL", value:"");\''
                                f" tag instead: '{tag_match.group(0)}'"
                            )

    def contains_nvd_mitre_link_in_xref(self) -> Iterator[LinterResult]:
        """
        Checks a given file if the script_xref(name:"URL", value:""); contains
        a link to an URL including any of this occurrence:

        - https://nvd.nist.gov/vuln/detail/CVE-

        - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-

        Background: Both links are already covered by the script_cve_id() tag
        and the Link is just a redundant information.

        Args:
                nasl_file: The VT that is going to be checked
                file_content: The content of the file that is going to be
                                checked
        """

        file_content = self.context.file_content
        pattern = get_special_script_tag_pattern(SpecialScriptTag.XREF)
        tag_matches = pattern.finditer(file_content)

        for match in tag_matches:
            if match:
                if (
                    # fmt: off
                    "nvd.nist.gov/vuln/detail/CVE-" in match.group('ref')
                    or "cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"
                    in match.group('ref')
                    # fmt: on
                ):
                    yield LinterError(
                        "The following script_xref is pointing "
                        "to Mitre/NVD which is already covered by the "
                        "script_cve_id. This is a redundant info and the "
                        f"script_xref needs to be removed: {match.group(0)}"
                    )

    @staticmethod
    def check_to_continue(http_link_match_group: AnyStr) -> bool:
        if (
            "The payloads try to open a connection to www.google.com"
            in http_link_match_group
        ):
            return True
        if (
            "The script attempts to connect to www.google.com"
            in http_link_match_group
        ):
            return True
        if (
            "to retrieve a web page from www.google.com"
            in http_link_match_group
        ):
            return True
        if "Subject: commonName=www.paypal.com" in http_link_match_group:
            return True
        if (
            "Terms of use at https://www.verisign.com/rpa"
            in http_link_match_group
        ):
            return True
        if (
            "example.com" in http_link_match_group
            or "example.org" in http_link_match_group
        ):
            return True
        if "www.exam" in http_link_match_group:
            return True
        if (
            "sampling the resolution of a name (www.google.com)"
            in http_link_match_group
        ):
            return True
        if "once with 'www.' and once without" in http_link_match_group:
            return True
        if "wget http://www.javaop.com/~ron/tmp/nc" in http_link_match_group:
            return True
        if (
            "Ncat: Version 5.30BETA1 (http://nmap.org/ncat)"
            in http_link_match_group
        ):
            return True
        if "as www.windowsupdate.com. (BZ#506016)" in http_link_match_group:
            return True
        if (
            "located at http://sambarserver/session/pagecount."
            in http_link_match_group
        ):
            return True
        if "http://rest.modx.com" in http_link_match_group:
            return True
        if (
            "ftp:// " in http_link_match_group
            or "ftp://'" in http_link_match_group
            or "ftp://)" in http_link_match_group
            or "ftp.c" in http_link_match_group
            or "ftp.exe" in http_link_match_group
        ):
            return True
        if (
            "using special ftp://" in http_link_match_group
            or "running ftp." in http_link_match_group
            or "ftp. The vulnerability" in http_link_match_group
        ):
            return True
        if (
            "'http://' protocol" in http_link_match_group
            or "handle <a href='http://...'> properly" in http_link_match_group
        ):
            return True
        if "Switch to git+https://" in http_link_match_group:
            return True
        if (
            "wget https://compromised-domain.com/important-file"
            in http_link_match_group
        ):
            return True
        if "the https:// scheme" in http_link_match_group:
            return True
        if "https://www.phishingtarget.com@evil.com" in http_link_match_group:
            return True
        # e.g.:
        # Since gedit supports opening files via 'http://' URLs
        if (
            "'http://'" in http_link_match_group
            or "'https://'" in http_link_match_group
        ):
            return True

        return False

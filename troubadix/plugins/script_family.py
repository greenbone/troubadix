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

from pathlib import Path
from typing import Iterator

from troubadix.helper.patterns import (
    SpecialScriptTag,
    get_special_script_tag_pattern,
)
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult

VALID_FAMILIES = [
    "AIX Local Security Checks",
    "AlmaLinux Local Security Checks",
    "Amazon Linux Local Security Checks",
    "Brute force attacks",
    "Buffer overflow",
    "CISCO",
    "CentOS Local Security Checks",
    "Citrix Xenserver Local Security Checks",
    "Compliance",
    "Credentials",
    "Databases",
    "Debian Local Security Checks",
    "Default Accounts",
    "Denial of Service",
    "F5 Local Security Checks",
    "FTP",
    "Fedora Local Security Checks",
    "FortiOS Local Security Checks",
    "FreeBSD Local Security Checks",
    "Gain a shell remotely",
    "General",
    "Gentoo Local Security Checks",
    "Huawei",
    "Huawei EulerOS Local Security Checks",
    "HP-UX Local Security Checks",
    "IT-Grundschutz",
    "IT-Grundschutz-deprecated",
    "IT-Grundschutz-15",
    "JunOS Local Security Checks",
    "Mac OS X Local Security Checks",
    "Mageia Linux Local Security Checks",
    "Malware",
    "Mandrake Local Security Checks",
    "Nmap NSE",
    "Nmap NSE net",
    "Oracle Linux Local Security Checks",
    "PCI-DSS",
    "PCI-DSS 2.0",
    "Palo Alto PAN-OS Local Security Checks",
    "Peer-To-Peer File Sharing",
    "Policy",
    "Port scanners",
    "Privilege escalation",
    "Product detection",
    "RPC",
    "Red Hat Local Security Checks",
    "Remote file access",
    "Rocky Linux Local Security Checks",
    "SMTP problems",
    "SNMP",
    "SSL and TLS",
    "Service detection",
    "Settings",
    "Slackware Local Security Checks",
    "Solaris Local Security Checks",
    "SuSE Local Security Checks",
    "Ubuntu Local Security Checks",
    "Useless services",
    "VMware Local Security Checks",
    "Web Servers",
    "Web application abuses",
    "Windows",
    "Windows : Microsoft Bulletins",
]


class CheckScriptFamily(FileContentPlugin):
    name = "check_script_family"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """This script checks VT for the existence / validity
        of its script family"""
        if nasl_file.suffix == ".inc":
            return

        family_pattern = get_special_script_tag_pattern(SpecialScriptTag.FAMILY)
        matches = list(family_pattern.finditer(file_content))

        if not matches:
            yield LinterError(
                "No script family exist",
                file=nasl_file,
                plugin=self.name,
            )
            return

        if len(matches) > 1:
            yield LinterError(
                "More then one script family exist",
                file=nasl_file,
                plugin=self.name,
            )
            return

        if matches[0].group("value") not in VALID_FAMILIES:
            yield LinterError(
                "Invalid or misspelled script family "
                f"'{matches[0].group('value')}'",
                file=nasl_file,
                plugin=self.name,
            )

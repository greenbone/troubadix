# Copyright (C) 2022 Greenbone AG
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

from troubadix.helper import is_ignore_file
from troubadix.helper.patterns import ScriptTag, get_script_tag_pattern

from troubadix.plugin import FileContentPlugin, LinterError, LinterResult

# nb: Those are files which are correctly using a log_message() to do e.g. some
# additional reporting for the user. This is a valid case which doesn't need to
# be changed. The example and template files shouldn't be checked at all because
# the plugin would throw an unnecessary error for them if e.g. not running from
# within the nasl/common folder. But all three files are just examples and don't
# need to be checked at all.
IGNORE_FILES = [
    "pre2008/domino_default_db.nasl",
    "pre2008/oracle_tnslsnr_security.nasl",
    "pre2008/smtp_AV_42zip_DoS.nasl",
    "pre2008/shoutcast_version.nasl",
    "2017/gb_default_http_credentials_report.nasl",
    "2017/gb_dcetest_report.nasl",
    "2021/gb_ntp_mode6_response_check.nasl",
    "GSHB/GSHB_WMI_get_Shares.nasl",
    "GSHB/GSHB_WMI_Loginscreen.nasl",
    "GSHB/GSHB_WMI_CD-FD-User-only-access.nasl",
    "gb_dicom_service_ae_title_brute_force.nasl",
    "Policy/policy_controls_fail.nasl",
    "2016/gb_ssl_tls_weak_hash_algo.nasl",
    "2018/gb_unquoted_path_vulnerabilities_win.nasl",
    "2009/remote-net-hub-3com.nasl",
    "2015/gb_vnc_brute_force.nasl",
    "2012/gb_secpod_ssl_ciphers_weak_report.nasl",
    "GSHB/GSHB_Kompendium.nasl",
    "/policy_control_template.nasl",
    "/template.nasl",
    "test_ipv6_packet_forgery.nasl",
    "test_version_func_inc.nasl",
    "pre2008/mssql_brute_force.nasl",
]


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

        if is_ignore_file(nasl_file, IGNORE_FILES):
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

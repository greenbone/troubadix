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
from pathlib import Path
from typing import Iterator

from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class CheckForkingNaslFunctions(FileContentPlugin):
    name = "check_forking_nasl_functions"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """This script checks if any of the following functions are used more
        than once or in conjunction with other mentioned functions within the
        same VT:

        - get_app_port();
        - get_app_port_from_list();
        - get_app_port_from_cpe_prefix();
        - service_get_port();
        - unknownservice_get_port();
        - ftp_get_port();
        - http_get_port();
        - telnet_get_port();
        - smtp_get_port();
        - pop3_get_port();
        - imap_get_port();
        - ssh_get_port();
        - tls_ssl_get_port();
        - ldap_get_port();
        - snmp_get_port();
        - sip_get_port_proto();
        - rsync_get_port();
        - nntp_get_port();
        - tcp_get_all_port();
        - udp_get_all_port();

        In addition, those specific functions *might* get a port from e.g.
        get_app_port() passed and are handled separately. These shouldn't be
        called together as well but the check is done independently of the
        ones above:

        - get_app_version();
        - get_app_location();
        - get_app_version_from_list();
        - get_app_version_and_location_from_list();
        - get_app_version_and_location();
        - get_app_location_and_proto();
        - get_app_version_and_proto();
        - get_app_full();
        - get_app_details();

        Args:
            nasl_file: The VT that is going to be checked
            file_content: The content of the file that is going to be checked
        """
        if nasl_file.suffix == ".inc":
            return

        # Those two are only calling http_get_port() if get_app_port() was
        # "empty".
        if "sw_magento_magmi_detect.nasl" in str(
            nasl_file
        ) or "2014/gb_apache_struts_classloader_vuln.nasl" in str(nasl_file):
            return

        # Those two are using if/else calls between
        # smtp_get_port/imap_get_port or get_app_port/service_get_port calls.
        if "2009/zabbix_37308.nasl" in str(
            nasl_file
        ) or "pre2008/mailenable_imap_rename_dos.nasl" in str(nasl_file):
            return

        # This one is using if/else calls similar to the examples above.
        if (
            "2011/zohocorp/gb_manageengine_adselfservice_plus_xss_vuln.nasl"
            in str(nasl_file)
        ):
            return

        # Another example using if/else calls
        if "gsf/2022/siemens/gb_sicam_a8000_ssa-316850.nasl" in str(nasl_file):
            return

        match = re.findall(
            r"\s*[=!]\s*((get_app_port|get_app_port_from_("
            r"cpe_prefix|list)|sip_get_port_proto|(tcp|udp)_get_all_port|("
            r"ftp|http|telnet|smtp|pop3|imap|ssh|tls_ssl|ldap|snmp|rsync|nntp"
            r"|unknownservice|service)_get_port)\s*\([^)]*\)\s*[;\)])",
            file_content,
        )
        if match and len(match) > 1:
            for tag in match:
                if tag[0]:
                    yield LinterError(
                        f"The VT is using the {tag[0]} "
                        "multiple times or in conjunction with other "
                        "forking functions. Please either use get_app_port_from"
                        "_list() from host_details.inc or split your VT into "
                        f"several VTs for each covered protocol.",
                        file=self.context.nasl_file,
                        plugin=self.name,
                    )
            return

        match = re.findall(
            r"\s*[=!]\s*(get_app_(version|location|version_from_list"
            r"|version_and_location_from_list|version_and_location"
            r"|location_and_proto|version_and_proto|full|details)\s*\(["
            r"^)]*\)\s*[;\)])",
            file_content,
        )
        if match and len(match) > 1:
            for tag in match:
                if tag[0]:
                    # some special cases, these are calling get_app_location
                    # with nofork:TRUE which returns a list instead of doing
                    # a fork.
                    exceptions = [
                        "2018/phpunit/gb_phpunit_rce.nasl",
                        "2018/gb_unprotected_web_app_installers.nasl",
                        "2018/gb_sensitive_file_disclosures_http.nasl",
                    ]
                    if any(e in str(nasl_file) for e in exceptions):
                        if "nofork:TRUE" in tag[0]:
                            continue

                    yield LinterError(
                        f"The VT is using the {tag[0]} multiple times or in "
                        "conjunction with other forking functions. Please use "
                        "e.g. get_app_version_and_location(), "
                        "get_app_version_and_location_from_list() or similar "
                        "functions from host_details.inc.",
                        file=self.context.nasl_file,
                        plugin=self.name,
                    )

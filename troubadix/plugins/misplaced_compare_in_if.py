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

from troubadix.helper import is_ignore_file
from troubadix.plugin import FilePlugin, LinterError, LinterResult

# nb: Those are files which have this misplaced compare since their very first
# version. As changing the if now might change their behavior and the VTs are
# candidates for deprecation they are ignored for now.
IGNORE_FILES = [
    "GSHB_WMI_Apache.nasl",
    "GSHB_WMI_EFS.nasl",
    "GSHB_WMI_Antivir.nasl",
    "GSHB_WMI_ProtectedMode.nasl",
    "GSHB_WMI_WinAdminTools.nasl",
    "GSHB_WMI_PolSecSet.nasl",
    "GSHB_WMI_BootDrive.nasl",
    "GSHB_WMI_W2K3_ClientFunk.nasl",
    "GSHB_WMI_IIS_Protect_SynAttack.nasl",
    "GSHB_WMI_NtpServer.nasl",
    "GSHB_WMI_IPSec_Policy.nasl",
    "GSHB_WMI_removable-media.nasl",
    "GSHB_WMI_get_AdminUsers.nasl",
    "GSHB_WMI_SNMP_Communities.nasl",
    "GSHB_WMI_IIS_UrlScanFilter.nasl",
    "GSHB_Read_Apache_Config.nasl",
    "GSHB_SMB_SDDL.nasl",
    "GSHB_WMI_IIS_RDS.nasl",
    "GSHB_WMI_PathVariables.nasl",
    "GSHB_WMI_Hibernate.nasl",
    "GSHB_Kompendium.nasl",
    "GSHB_WMI_XP-InetComm.nasl",
    "GSHB_WMI_EventLogPolSet.nasl",
    "GSHB_WMI_get_Shares.nasl",
    "GSHB_WMI_CD-FD-User-only-access.nasl",
    "GSHB_WMI_IIS_Samplefiles.nasl",
    "GSHB_WMI_list_Services.nasl",
    "GSHB_WMI_TerminalServerSettings.nasl",
    "GSHB_WMI_Driver-Autostart.nasl",
    "GSHB_WMI_Loginscreen.nasl",
    "GSHB_WMI_IIS_exec_cmd.nasl",
    "GSHB_WMI_AllowRemoteDASD.nasl",
    "GSHB_WMI_Passfilt.nasl",
    "GSHB_WMI_ScreenSaver_Status.nasl",
    "GSHB_WMI_WinFirewallStat.nasl",
    "GSHB_WMI_CD-Autostart.nasl",
    "GSHB_WMI_WIN_Subsystem.nasl",
    "GSHB_WMI_pre2000comp.nasl",
    "GSHB_WMI_PasswdPolicie.nasl",
    "GSHB_WMI_DomContrTest.nasl",
    "GSHB_WMI_get_ODBCINST.nasl",
]


class CheckMisplacedCompareInIf(FilePlugin):
    name = "check_misplaced_compare_in_if"

    def run(self) -> Iterator[LinterResult]:
        """This script checks the passed VT/Include if it is using a misplaced
            compare within an if() call like e.g.:

            if( variable >< "text" ) {}
            if( variable >< 'text' ) {}
            if( variable >!< "text" ) {}
            if( variable >!< 'text' ) {}

            instead of:

            if( "text" >< variable ) {}
            if( "text" >!< variable ) {}

        Args:
            nasl_file: The VT/Include that is going to be checked
            file_content: The content of the VT
        """

        if is_ignore_file(self.context.nasl_file, IGNORE_FILES):
            return

        # pylint: disable=W0511
        # TODO: Find a better way to parse if calls as this would miss
        #  something like e.g.:
        #
        # if((foo =~ "bar || bar =~ "foo") || foobar = "foo"){}
        #
        # nb: We can't use { as an ending delimiter as there could be also
        #  something like e.g.:
        #
        # if((foo =~ "bar || bar =~ "foo") || foobar = "foo")
        #   bar = "foo"; (no ending {)
        # maybe this regex fixes this:
        #   r"^\s*(if|}?\s*else if)\s*\((?P<condition>.*)\)\s*({|(.*|.*\n.*);)"
        # original regex:
        #   r"^\s*(if|}?\s*else if)\s*\(([^)]+)"
        if_matches = re.finditer(
            r"^\s*(if|}?\s*else if)\s*\((?P<condition>.*)\)\s*({|(.*|.*\n.*);)",
            self.context.file_content,
            re.MULTILINE,
        )

        if not if_matches:
            return

        for if_match in if_matches:
            if if_match:
                misplaced_compare_match = re.search(
                    r"((if|}?\s*else if)\s*\("
                    r"\s*|\|\|\s*|&&\s*)["
                    r"a-zA-Z_]+\s*>\!?<\s*("
                    r'"|\')',
                    if_match.group(0),
                )
                if misplaced_compare_match:
                    yield LinterError(
                        f"VT/Include is using a misplaced compare "
                        f"within an if() call in {if_match.group(0)}",
                        file=self.context.nasl_file,
                        plugin=self.name,
                    )

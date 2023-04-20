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

from troubadix.plugin import (
    FileContentPlugin,
    LinterError,
    LinterResult,
    LinterWarning,
)


class CheckUsingDisplay(FileContentPlugin):
    name = "check_using_display"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        if "# troubadix: disable=template_nd_test_files_fps" in file_content:
            return

        display_matches = re.finditer(
            r".*(display\s*\([^)]+\)\s*;)", file_content
        )
        if display_matches is None:
            return

        for display_match in display_matches:
            if display_match is not None and display_match.group(0):
                dis_match = display_match.group(0)
                file_name = str(nasl_file)

                # Known false positives because the if_match check above can't
                # detect something like e.g.:
                # if( debug )
                #   display("foo");
                if (
                    "ssh_func.inc" in file_name
                    and "display( debug_str )" in dis_match
                ):
                    continue

                if (
                    "gb_treck_ip_stack_detect.nasl" in file_name
                    and 'display("---[' in dis_match
                ):
                    continue

                if (
                    "ike_isakmp_func.inc" in file_name
                    and 'display( "---[' in dis_match
                ):
                    continue

                if (
                    "pcap_func.inc" in file_name
                    and 'display( "---[' in dis_match
                ):
                    continue

                if (
                    "os_eol.inc" in file_name
                    and 'display( "DEBUG: Base CPE' in dis_match
                ):
                    continue

                if (
                    "gsf/dicom.inc" in file_name
                    or "enterprise/dicom.inc" in file_name
                    or "global_settings.inc" in file_name
                    or "rdp.inc" in file_name
                    or "bin.inc" in file_name
                ):
                    continue

                if (
                    "DDI_Directory_Scanner.nasl" in file_name
                    and ":: Got a" in dis_match
                ):
                    continue

                if_comment_match = re.search(
                    r"(if[\s]*\(|#).*display\s*\(", dis_match
                )
                if (
                    if_comment_match is not None
                    and if_comment_match.group(0) is not None
                ):
                    yield LinterWarning(
                        f"VT is using a display() function which "
                        f"is protected by a comment or an if statement at: "
                        f"{dis_match}.",
                        file=nasl_file,
                        plugin=self.name,
                    )
                else:
                    yield LinterError(
                        f"VT/Include is using a display() "
                        f"function at: {dis_match}",
                        file=nasl_file,
                        plugin=self.name,
                    )

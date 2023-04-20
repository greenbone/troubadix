# SPDX-FileCopyrightText: 2021 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import re
from pathlib import Path
from typing import Iterable, Iterator

from troubadix.helper import is_ignore_file
from troubadix.plugin import LineContentPlugin, LinterError, LinterResult

_IGNORE_FILES = (
    "sw_telnet_os_detection.nasl",
    "gb_hp_comware_platform_detect_snmp.nasl",
    "gb_hirschmann_telnet_detect.nasl",
)

_FULL_IGNORE_FILES = (
    "test_version_func_inc.nasl",
    "policy_control_template.nasl",
    "template.nasl",
    "test_ipv6_packet_forgery.nasl",
)


class CheckCopyrightYear(LineContentPlugin):
    """This steps checks if a VT contains a Copyright statement containing a
    year not matching the year defined in the creation_date statement like
    script_tag(name:"creation_date", value:"2017-
    """

    name = "check_copyright_year"

    def check_lines(
        self,
        nasl_file: Path,
        lines: Iterable[str],
    ) -> Iterator[LinterResult]:
        if nasl_file.suffix == ".inc" or is_ignore_file(
            nasl_file, _FULL_IGNORE_FILES
        ):
            return

        creation_date = ""
        creation_year = ""
        copyrights = []

        for i, line in enumerate(lines, 1):
            if "creation_date" in line:
                expre = re.search(r'value\s*:\s*"(.*)"', line)
                if expre is not None and expre.group(1) is not None:
                    creation_date = expre.group(1)
                    expre = re.search(r"^([0-9]+)-", creation_date)
                    if expre is not None and expre.group(1) is not None:
                        creation_year = expre.group(1)

            copyright_match = re.search(
                r"((# |script_copyright.+)[Cc]opyright \([Cc]\)|"
                r"# SPDX-FileCopyrightText:) ([0-9]+)",
                line,
            )
            if (
                copyright_match is not None
                and copyright_match.group(3) is not None
                and not is_ignore_file(nasl_file, _IGNORE_FILES)
            ):
                copyrights.append((i, line, copyright_match.group(3)))

        if not creation_year:
            yield LinterError(
                "Missing creation_date statement in VT",
                file=nasl_file,
                plugin=self.name,
            )

        # key is the line where the copyright is found, value the year found
        # within that line
        for nr, line, copyright_year in copyrights:
            if copyright_year != creation_year:
                if "pre2008" in str(nasl_file):
                    if copyright_year > creation_year:
                        yield LinterError(
                            "VT contains a Copyright year not matching "
                            f"the creation year {creation_year} at line {nr}",
                            file=nasl_file,
                            plugin=self.name,
                            line=nr,
                        )
                else:
                    yield LinterError(
                        "VT contains a Copyright year not matching "
                        f"the creation year {creation_year} at line {nr}",
                        file=nasl_file,
                        plugin=self.name,
                        line=nr,
                    )

# Copyright (C) 2021 Greenbone Networks GmbH
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

""" checking badwords in NASL scripts with the NASLinter """

from pathlib import Path
from typing import Iterable, Iterator

from troubadix.helper import is_ignore_file
from troubadix.plugin import LineContentPlugin, LinterError, LinterResult

# hexstr(OpenVAS) = '4f70656e564153'
# hexstr(openvas) = '6f70656e766173'
DEFAULT_BADWORDS = [
    "cracker",
    "openvas",
    "OpenVAS",
    "4f70656e564153",
    "6f70656e766173",
]

_IGNORE_FILES = [
    "gb_openvas",
    "gb_gsa_",
    "http_func.inc",
    "misc_func.inc",
    "OpenVAS_detect.nasl",
]

EXCEPTIONS = [
    "openvas-nasl",
    "openvas-smb",
    "openvas-scanner",
    "openvas-libraries",
    "openvas-gsa",
    "openvas-cli",
    "openvas-manager",
    "openvassd",
    "lists.wald.intevation.org",
    "lib64openvas-devel",
    "lib64openvas6",
    "libopenvas-devel",
    "libopenvas6",
    "cpe:/a:openvas",
    "OPENVAS_VERSION",
    "openvas.org",
    "get_preference",
    "OPENVAS_USE_LIBSSH",
    "github.com/greenbone",
    "Cookie: mstshash=openvas",
    "smb_nt.inc",
    "lanman",
    "OpenVAS_detect.nasl",
    "OpenVAS TCP Scanner",
    "openvas_tcp_scanner",
    "gb_openvas_",
    "OpenVAS_detect.nasl",
    "OpenVAS Manager",
    "OpenVAS Administrator",
    "OpenVAS / Greenbone Vulnerability Manager",
]

STARTS_WITH_EXCEPTIONS = [
    "# OpenVAS Vulnerability Test",
    "# OpenVAS Include File",
    "  script_",
    "# $Id: ",
]

COMBINED = [("find_service3.nasl", "OpenVAS-")]


class CheckBadwords(LineContentPlugin):
    """This plugin checks the passed VT for the use of any of
    the defined badwords. An error will be thrown if the VT contains
    such a badword.
    """

    name = "check_badwords"

    def check_lines(
        self,
        nasl_file: Path,
        lines: Iterable[str],
    ) -> Iterator[LinterResult]:
        if is_ignore_file(nasl_file, _IGNORE_FILES):
            return

        for i, line in enumerate(lines, 1):
            if any(badword in line for badword in DEFAULT_BADWORDS):
                if (
                    not any(exception in line for exception in EXCEPTIONS)
                    and not any(
                        line.startswith(start)
                        for start in STARTS_WITH_EXCEPTIONS
                    )
                    and not any(
                        nasl_file.name == filename and value in line
                        for filename, value in COMBINED
                    )
                ):
                    yield LinterError(
                        f"Badword in line {i:5}: {line}",
                        plugin=self.name,
                        file=nasl_file,
                        line=i,
                    )

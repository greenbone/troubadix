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
    "'OpenVAS Manager",
    "OpenVAS Administrator",
    "OpenVAS / Greenbone Vulnerability Manager",
]

STARTS_WITH_EXCEPTIONS = [
    "# OpenVAS Vulnerability Test",
    "# OpenVAS Include File",
    "  script_",
    "# $Id: ",
]

# (file, exception) #to do... integrate this into badword check
COMBINED = [("find_service3.nasl", "OpenVAS-")]


class CheckBadwords(LineContentPlugin):
    """This steps checks if a VT contains a Copyright statement containing a
    year not matching the year defined in the creation_date statement like
    script_tag(name:"creation_date", value:"2017-
    """

    name = "check_badwords"

    @staticmethod
    def run(
        nasl_file: Path,
        lines: Iterable[str],
    ) -> Iterator[LinterResult]:
        if is_ignore_file(nasl_file, _IGNORE_FILES):
            return

        for i, line in enumerate(lines):
            if any(badword in line for badword in DEFAULT_BADWORDS):
                if not any(
                    exception in line for exception in EXCEPTIONS
                ) and not any(
                    line.startswith(start) for start in STARTS_WITH_EXCEPTIONS
                ):
                    yield LinterError(f"Badword in line {i+1:5}: {line}")

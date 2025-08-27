# Copyright (C) 2021 Greenbone AG
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

"""checking badwords in NASL scripts with the NASLinter"""

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
    # nb: VT/vt should be used instead
    "NVT",
    "nvt",
]

_IGNORE_FILES = [
    "gb_openvas",
    "gb_gsa_",
    "gb_greenbone_gsa_",
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
    "openvasd",
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
    "openvas_1808149858",
    "OSPD-OpenVAS",
    "evil.zip -> openvas.jsp",
    'url = "/openvas.jsp";',
    'if( "OpenVAS RCE Test" >< buf )',
    'the file "/openvas.jsp" was created',
    "/var/lib/openvas/plugins/",
    "INVT ",  # INVT Electric VT Designer
    "invt_",  # cpe:/a:invt_electric
    "HostDetails/NVT",  # Can't be changed right now...
    ", nvt:",  # Can't be changed right now...
    "Hu1nvt5qm",  # Part of a bigger blob
    "gz3nvtPjk",  # Same as above
    "0EAnvtBAK",  # Same as above
    "technocrackers",  # Author name of a wordpress plugin
    "Technocrackers",  # Author name of a wordpress plugin
    "firecracker",  # Valid package name on e.g. Fedora
    "Firecracker",  # Valid package name on e.g. Fedora
    "pcp-pmda-nutcracker",  # Valid package name on e.g. openSUSE or Arch Linux
    # We should generally exclude http:// and https:// URLs as these are
    # immutable and shouldn't be changed / require separate exclusions for each
    "https://",
    "http://",
]

STARTS_WITH_EXCEPTIONS = [
    "  script_",
]

COMBINED = [
    ("find_service3.nasl", "OpenVAS-"),
    # nb:
    # - Only used as variables/function parameters and not user facing
    # - Will be changed in one go in the future and we don't need to
    #   report this on every plugin run
    ("host_details.inc", "nvt"),
]


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
                    report = f"Badword in line {i:5}: {line}"
                    if "NVT" in line:
                        report += (
                            '\nNote/Hint: Please use the term "VT" instead.'
                        )
                    yield LinterError(
                        report,
                        plugin=self.name,
                        file=nasl_file,
                        line=i,
                    )

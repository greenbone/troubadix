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
from typing import List

# hexstr(OpenVAS) = '4f70656e564153'
# hexstr(openvas) = '6f70656e766173'
DEFAULT_BADWORDS = ["cracker", "openvas", "4f70656e564153", "6f70656e766173"]

IGNORE_FILES = [
    "gb_openvas",
    "gb_gsa_",
    "http_func.inc",
    "misc_func.inc",
]

EXCEPTIONS = [
    "opvenas-nasl",
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


def _badwords(
    nasl_file: Path,
    badwords: List[str],
):
    # ignore files
    lines = nasl_file.read_text(encoding="utf-8").split("\n")
    line_number = 0
    badword_found = False
    output = f"Badword(s) found in {nasl_file}\n"
    for line in lines:
        if any(badword in line for badword in badwords) and not any(
            exception in line for exception in EXCEPTIONS
        ):
            output += f"line {line_number:5}: {line}\n"
            badword_found = True
        line_number = line_number + 1
    if badword_found:
        print(output)


def find_badwords(
    nasl_files: List[str],
    badwords: List[str] = None,
    ignore_files: List[str] = None,
):
    if not badwords:
        badwords = DEFAULT_BADWORDS
    if not ignore_files:
        ignore_files = IGNORE_FILES
    for nasl_file in nasl_files:
        if any(ignore in str(nasl_file) for ignore in ignore_files):
            print(f"Ignoring file {nasl_file}")
        else:
            _badwords(
                nasl_file=nasl_file,
                badwords=badwords,
            )


def main():
    find_badwords([Path(__file__), Path("foo/gb_gsa_bla.nasl")])


if __name__ == "__main__":
    main()

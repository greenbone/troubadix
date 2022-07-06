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

from validators import url

from troubadix.helper.patterns import get_xref_pattern
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult

ALLOWED_URLS = [
    "https://lists.apache.org/thread.html/e1ef853fc0079cdb55be"
    "fbd2dac042934e49288b476d5f6a649e5da2@<announce.tomcat.apache.org>",
    "https://lists.apache.org/thread.html/e1ef853fc0079cdb55be"
    "fbd2dac042934e49288b476d5f6a649e5da2@<announce.tomcat.apache.org>",
    "https://m0ze.ru/vulnerability/[2021-05-26]-[WordPress]-[C"
    "WE-79]-WP-Reset-WordPress-Plugin-v1.86.txt",
    "http://yehg.net/lab/pr0js/advisories/joomla/core/[joomla_"
    "1.0.x~15]_cross_site_scripting",
    "http://yehg.net/lab/pr0js/advisories/eclipse/[eclipse_hel"
    "p_server]_cross_site_scripting",
    "http://core.yehg.net/lab/pr0js/advisories/dll_hijacking/["
    "flash_player]_10.1.x_insecure_dll_hijacking_(dwmapi.dll)",
    "https://lists.apache.org/thread.html/773c93c2d8a6a52bbe9"
    "7610c2b1c2ad205b970e1b8c04fb5b2fccad6@<general.hadoop.apache.org>",
    "http://mail-archives.apache.org/mod_mbox/perl-advocacy/2"
    "00904.mbox/<ad28918e0904011458h273a71d4x408f1ed286c9dfbc@mail.gmail.com>",
    "http://yehg.net/lab/pr0js/advisories/[mybb1.6]_cross_site_scripting",
]


class CheckScriptXrefUrl(FileContentPlugin):
    name = "check_script_xref_url"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """
        Checks if a URL type script_xref call contains a valid URL
        """
        if nasl_file.suffix == ".inc":
            return

        matches = get_xref_pattern(name="URL", value=r".+?").finditer(
            file_content
        )
        for match in matches:
            if match:
                if not match.group("value") in ALLOWED_URLS and not url(
                    match.group("value")
                ):
                    yield LinterError(
                        f"{match.group(0)}: Invalid URL value",
                        file=nasl_file,
                        plugin=self.name,
                    )

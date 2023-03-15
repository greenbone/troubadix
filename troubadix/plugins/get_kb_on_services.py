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


class CheckGetKBOnServices(FileContentPlugin):
    name = "check_get_kb_on_services"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """
        Checks a given file if it is accessing one or more "Services/" KB keys
        like e.g.

        get_kb_item("Services/www");
        get_kb_list("Services/udp/upnp");

        These calls should use a "wrapping" function like e.g. the following
        (depending on the Service KB key) instead:

        http_get_port()
        service_get_port()
        service_get_ports()

        Args:
                nasl_file: The VT that is going to be checked
                file_content: The content of the file that is going to be
                              checked

        """
        if nasl_file.suffix == ".inc":
            return

        kb_matches = re.finditer(
            r'(get_kb_(?P<type>item|list)\s*\(\s*(?P<quote>[\'"])(?P<value>'
            r"Services/[^)]+)\))",
            file_content,
        )
        if kb_matches:
            for kb_match in kb_matches:
                if kb_match:
                    # special cases where not function currently exists
                    if "Services/tcp/*" in kb_match.group(
                        "value"
                    ) or "Services/udp/*" in kb_match.group("value"):
                        continue

                    # another special case, the find_service*.nasl need to
                    # access "Services/unknown" directly.
                    # The same is valid for unknown_services.nasl as well.
                    if "unknown_services.nasl" in str(nasl_file) or re.search(
                        r"find_service([0-9]+|_("
                        r"3digits|spontaneous|nmap|nmap_wrapped))?\.nasl",
                        str(nasl_file),
                    ):
                        continue

                    # an additional special case, this needs to access the
                    # KB key directly
                    if "2017/gb_hp_printer_rce_vuln.nasl" in str(nasl_file):
                        continue

                    yield LinterError(
                        f"The following get_kb_{kb_match.group('type')}() call"
                        " should use a function instead of a direct access to "
                        f"the Services/KB key: {kb_match.group('value')}",
                        file=self.context.nasl_file,
                        plugin=self.name,
                    )

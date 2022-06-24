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

import re
from pathlib import Path
from typing import Iterator

from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class CheckScriptCopyright(FileContentPlugin):
    name = "check_script_copyright"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """This plugin checks a VT for the correct use of the copyright text.

        Prior to this plugin, most VTs had used a
        'script_copyright("This script is Copyright (C) [...]");'
        tag, however the introductory text ("This script is") is to be discarded
        from now on.

        In addition this plugin will also report if the syntax of the
        'script_copyright();' tag is generally missing or malformed.

        Args:
            nasl_file: The VT that shall be checked
            file_content: str representing the file content
        """
        if nasl_file.suffix == ".inc":
            return

        if not re.search(
            r'script_copyright\("Copyright \(C\) [0-9]{4}', file_content
        ):
            yield LinterError(
                "The VT is using an incorrect syntax for its "
                "copyright statement. Please start (EXACTLY) with: "
                "'script_copyright(\"Copyright (C)' followed by the year "
                "(matching the one in creation_date) and the author/company.",
                file=nasl_file,
                plugin=self.name,
            )

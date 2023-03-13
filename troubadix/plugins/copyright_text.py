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

from troubadix.helper import CURRENT_ENCODING
from troubadix.plugin import (
    FileContentPlugin,
    LinterError,
    LinterFix,
    LinterResult,
)

CORRECT_COPYRIGHT_PHRASE = (
    "# Some text descriptions might be excerpted from (a) referenced\n"
    "# source(s), and are Copyright (C) by the respective right holder(s)."
)


class CheckCopyrightText(FileContentPlugin):
    name = "check_copyright_text"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """This plugin will report any occurrence of the following outdated text
        pattern:

        # Text descriptions are largely excerpted from the referenced
        # advisory, and are Copyright (C) of their respective author(s)

        or:

        # Text descriptions are largely excerpted from the referenced
        # advisory, and are Copyright (C) the respective author(s)

        or:

        # Text descriptions are largely excerpted from the referenced
        # advisory, and are Copyright (C) the respective author(s)

        or:

        # Some text descriptions might be excerpted from the referenced
        # advisories, and are Copyright (C) by the respective right holder(s)

        which should be the following from now on:

        # Some text descriptions might be excerpted from (a) referenced
        # source(s), and are Copyright (C) by the respective right holder(s).
        """
        self.new_file_content = None

        if nasl_file.suffix == ".inc":
            return

        match = re.search(
            r"^# (Text descriptions are largely excerpted from the referenced"
            r"\n# advisory, and are Copyright \([cC]\) (of )?(the|their) resp"
            r"ective author\(s\)|Some text descriptions might be excerpted from"
            r" the referenced\n# advisories, and are Copyright \(C\) by the "
            r"respective right holder\(s\))",
            file_content,
            re.MULTILINE,
        )
        if match:
            self.new_file_content = file_content.replace(
                match.group(0),
                CORRECT_COPYRIGHT_PHRASE,
            )

            yield LinterError(
                "The VT is using an incorrect copyright statement.",
                file=nasl_file,
                plugin=self.name,
            )

    def fix(self) -> Iterator[LinterResult]:
        if not self.new_file_content:
            return

        nasl_file = self.context.nasl_file
        nasl_file.write_text(
            data=self.new_file_content, encoding=CURRENT_ENCODING
        )

        yield LinterFix(
            f"The copyright statement has been updated to "
            f"{CORRECT_COPYRIGHT_PHRASE}",
            file=nasl_file,
            plugin=self.name,
        )

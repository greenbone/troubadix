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
from typing import Iterator, OrderedDict

from troubadix.plugin import FileContentPlugin, LinterError, LinterResult

CORRECT_COPYRIGHT_PHRASE = (
    "# Some text descriptions might be excerpted from (a) referenced\n"
    "# source(s), and are Copyright (C) by the respective right holder(s)."
)


class CheckCopyrightText(FileContentPlugin):
    name = "check_copyright_text"

    @staticmethod
    def run(
        nasl_file: Path,
        file_content: str,
        *,
        tag_pattern: OrderedDict[str, re.Pattern],
        special_tag_pattern: OrderedDict[str, re.Pattern],
    ) -> Iterator[LinterResult]:
        """This step checks a VT for the correct use of the copyright text.

        Prior to this step, most VTs are using
        "This script is Copyright (C) [...]",
        however the introductory text ("This script is") is to be discarded
        from now on.

        In addition it will also report any occurrence of the following
        outdated text pattern:

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
        del tag_pattern, special_tag_pattern

        if not re.search(
            r'script_copyright\("Copyright \(C\) [0-9]{4}', file_content
        ):
            yield LinterError(
                "The VT is using an incorrect syntax for its copyright "
                "statement. Please start (EXACTLY) with:\n"
                "'script_copyright(\"Copyright (C) followed by the year "
                "(matching the one in creation_date) and the author/company."
            )

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
            file_content = file_content.replace(
                match.group(0),
                CORRECT_COPYRIGHT_PHRASE,
            )

            nasl_file.write_text(data=file_content, encoding="latin1")
            yield LinterError(
                "The VT was using an incorrect copyright statement. Replaced "
                f"with:\n{CORRECT_COPYRIGHT_PHRASE}"
            )
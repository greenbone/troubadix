#  Copyright (c) 2022 Greenbone Networks GmbH
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
from typing import Iterator, OrderedDict

from troubadix.helper import get_tag_pattern
from troubadix.helper.patterns import ScriptTag
from troubadix.plugin import LinterError, FileContentPlugin, LinterResult


class CheckSolutionText(FileContentPlugin):
    name = "check_solution_text"

    @staticmethod
    def run(
        nasl_file: Path,
        file_content: str,
        *,
        tag_pattern: OrderedDict[str, re.Pattern],
        special_tag_pattern: OrderedDict[str, re.Pattern],
    ) -> Iterator[LinterResult]:
        """There are specific guidelines on the syntax for the solution tag on
        VTs with the solution_type "NoneAvailable" or "WillNotFix" available at:

        https://community.greenbone.net/t/vt-development/226 (How to handle VTs
        with "no solution" for the user)

        This script checks if those guidelines are upheld.

        Args:
            nasl_file: Name of the VT to be checked
            file_content: Content of the nasl_file to be checked

        """
        del tag_pattern, special_tag_pattern
        # Two different strings, one for RegEx one for output
        correct_none_available_pattern = (
            r"script_tag\s*\("
            r'\s*name\s*:\s*"solution"\s*,'
            r'\s*value\s*:\s*"No\s+known\s+solution\s+is\s+available\s+as\s+of'
            r"\s+(0[1-9]|[12][0-9]|3[01])(st|nd|rd|th)\s+(January|February|"
            r"March|April|May|June|July|August|September|October|November|"
            r"December),\s+20[0-9]{2}\.\s+Information\s+regarding\s+this\s+"
            r"issue\s+will\s+be\s+updated\s+once\s+solution\s+details\s+"
            r"are\s+available\."
        )
        correct_none_available_syntax = (
            '  script_tag(name:"solution", '
            'value:"No known solution is '
            "available as of dd(st|nd|rd|th) mmmmmmmm, yyyy.\n  "
            "Information regarding this issue will be updated once solution "
            'details are available.");'
        )

        # same here
        correct_will_not_fix_pattern = (
            r"script_tag\s*\("
            r'\s*name\s*:\s*"solution"\s*,\s*value\s*:\s*"(No\s+solution\s+'
            r"(was\s+made\s+available\s+by\s+the\s+vendor|is\s+required)\."
            r"\s+Note:.+|(No\s+solution\s+was\s+made\s+available\s+by\s+"
            r"the\s+vendor|No\s+known\s+solution\s+was\s+made\s+available\s+"
            r"for\s+at\s+least\s+one\s+year\s+since\s+the\s+disclosure\s+of"
            r"\s+this\s+vulnerability\.\s+Likely\s+none\s+will\s+be\s+provided"
            r"\s+anymore)\.\s+General\s+solution\s+options\s+are\s+to\s+"
            r"upgrade\s+to\s+a\s+newer\s+release,\s+disable\s+respective\s+"
            r"features,\s+remove\s+the\s+product\s+or\s+replace\s+the\s+product"
            r"\s+by\s+another\s+one\.)"
        )
        correct_will_not_fix_syntax = (
            '  script_tag(name:"solution", '
            'value:"No known solution was made '
            "available for at least one year\n  since the disclosure of this "
            "vulnerability. Likely none will be provided anymore. General "
            "solution\n  options are to upgrade to a newer release, disable "
            "respective features, remove the product or\n  replace the "
            'product by another one.");\n\n'
            '  script_tag(name:"solution", '
            'value:"No solution was made '
            "available by the vendor. General solution\n  options are to "
            "upgrade to a newer release, disable respective features, remove "
            'the product or\n  replace the product by another one.");\n\n'
            '  script_tag(name:"solution", '
            'value:"No solution was made '
            "available by the vendor.\n\n  Note: "
            '<add a specific note for the reason here>.");\n\n'
            '  script_tag(name:"solution", '
            'value:"No solution is required.\n\n  Note: <add a specific note '
            'for the reason here, e.g. CVE was disputed>.");'
        )

        if get_tag_pattern(
            name=ScriptTag.SOLUTION_TYPE, value="NoneAvailable"
        ).search(file_content) and not re.search(
            correct_none_available_pattern, file_content
        ):
            yield LinterError(
                "The VT with solution type 'NoneAvailable' is using an "
                "incorrect syntax in the solution text. Please use "
                f"(EXACTLY):\n{correct_none_available_syntax}",
            )
        elif get_tag_pattern(
            name=ScriptTag.SOLUTION_TYPE, value="WillNotFix"
        ).search(file_content) and not re.search(
            correct_will_not_fix_pattern, file_content
        ):
            yield LinterError(
                "The VT with solution type 'WillNotFix' is using an incorrect "
                "syntax in the solution text. Please use one of these "
                f"(EXACTLY):\n{correct_will_not_fix_syntax}",
            )
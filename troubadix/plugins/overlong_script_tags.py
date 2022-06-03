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

from troubadix.helper import is_ignore_file
from troubadix.helper.patterns import get_script_tag_patterns

from ..plugin import FileContentPlugin, LinterError, LinterResult

# Arbitrary limit adopted from original step
VALUE_LIMIT = 3000

IGNORE_FILES = [
    "gb_nmap6_",
    "monstra_cms_mult_vuln",
    "gb_huawei-sa-",
    "lsc_options.nasl",
]


class CheckOverlongScriptTags(FileContentPlugin):
    """This steps checks if the script_tag summary, impact,
    affected, insight, vuldetect or solution of a given VT
    contains an overlong line within the value string.

    Background for this is that (e.g. auto generated LSCs)
    are created by parsing an advisory and the whole
    content is placed in such a tag which could be quite large.
    """

    name = "check_overlong_script_tags"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        if nasl_file.suffix == ".inc":
            return

        if is_ignore_file(nasl_file, IGNORE_FILES):
            return

        script_tag_patterns = get_script_tag_patterns()
        for tag, pattern in script_tag_patterns.items():
            for match in pattern.finditer(file_content):
                if len(match.group("value")) > VALUE_LIMIT:
                    yield LinterError(
                        f"Tag {tag.value} is to long"
                        f" with {len(match.group('value'))} characters. "
                        f"Max {VALUE_LIMIT}",
                        file=nasl_file,
                        plugin=self.name,
                    )

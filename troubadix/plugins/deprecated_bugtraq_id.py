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

# pylint: disable=fixme

from typing import Iterator

from troubadix.helper import SpecialScriptTag
from troubadix.helper.patterns import get_special_script_tag_pattern
from troubadix.plugin import FilePlugin, LinterError, LinterResult


class CheckDeprecatedBugtraqId(FilePlugin):
    name = "check_deprecated_dependency"

    def run(self) -> Iterator[LinterResult]:
        """
        Search for deprecated script_bugtraq_id()
        """

        bugtraq_id_pattern = get_special_script_tag_pattern(
            SpecialScriptTag.BUGTRAQ_ID
        )
        matches = bugtraq_id_pattern.search(self.context.file_content)
        if not matches:
            return
        else:
            yield LinterError(
                "Found bugtraq id.",
                file=self.context.nasl_file,
                plugin=self.name,
            )

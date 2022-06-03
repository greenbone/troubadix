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

from enum import Enum
from pathlib import Path
from typing import Iterator

from troubadix.helper.patterns import (
    SpecialScriptTag,
    _get_special_script_tag_pattern,
)
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class ValidType(Enum):
    CHECKBOX = "checkbox"
    PASSWORD = "password"
    FILE = "file"
    RADIO = "radio"
    ENTRY = "entry"


class CheckScriptAddPreferenceType(FileContentPlugin):
    name = "check_script_add_preference_type"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """This script checks the passed VT if it is using a
        script_add_preference not matching one of the following
        allowed strings passed to the 'type' function parameter:

            - checkbox
            - password
            - file
            - radio
            - entry

        Args:
            file: The VT that is going to be checked
        """

        if nasl_file.suffix == ".inc":
            return

        # don't need to check VTs not having a script_add_preference() call
        if "script_add_preference" not in file_content:
            return

        preferences_matches = _get_special_script_tag_pattern(
            name=SpecialScriptTag.ADD_PREFERENCE.value,
            value=r'type\s*:\s*(?P<quote>[\'"])(?P<type>[^\'"]+)'
            r"(?P=quote)\s*[^)]*",
        ).finditer(file_content)

        for preferences_match in preferences_matches:
            if preferences_match:

                pref_type = preferences_match.group("type")
                if pref_type not in [t.value for t in ValidType]:

                    # nb: This exists since years and it is currently
                    # unclear if we can change it so
                    # we're excluding it here for now.
                    if (
                        "ssh_authorization_init.nasl" in nasl_file.name
                        and pref_type == "sshlogin"
                    ):
                        continue

                    yield LinterError(
                        "VT is using an invalid or misspelled string "
                        f"({pref_type}) passed to the type parameter of "
                        "script_add_preference in "
                        f"'{preferences_match.group(0)}'",
                        file=nasl_file,
                        plugin=self.name,
                    )

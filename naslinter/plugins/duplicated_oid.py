# Copyright (c) 2022 Greenbone Networks GmbH
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

from naslinter.helper import subprocess_cmd
from naslinter.plugin import (
    FileContentPlugin,
    LinterError,
    LinterMessage,
    LinterResult,
)


class CheckDuplicatedOID(FileContentPlugin):
    name = "check_duplicate_oid"

    @staticmethod
    def run(nasl_file: Path, file_content: str) -> Iterator[LinterResult]:
        """This script reads the OID from the file and runs grep to find out if
        the OID is used in more than one file.

        Args:
            nasl_file: The VT that is going to be checked
            file_content: The content of the file

        """

        oid = re.search(r'script_oid\("([0-9.]+)"\);', file_content)

        if oid:
            files = subprocess_cmd(
                f"grep -R 'script_oid(\"{oid.group(1)}\");' . --include=*.nasl"
            ).splitlines()
            files.sort()
            file_count = len(files)
            if file_count == 1:
                return
            else:
                output_text = (
                    f"Duplicated OID '{oid.group(1)}' in VT '{nasl_file}'"
                    " already in use in following files:"
                )
                for i in range(0, file_count):
                    if re.search(str(nasl_file), files[i]) is None:
                        output_text += f"\r\n- {files[i]}"
                yield LinterError(output_text)
                return
        else:
            yield LinterMessage(f"No OID found in VT '{nasl_file}'")
            return

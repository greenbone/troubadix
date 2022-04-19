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
import subprocess
from pathlib import Path
from typing import Iterable, Iterator

from troubadix.plugin import LineContentPlugin, LinterError, LinterResult

# Only the ASCII and extended ASCII for now... # https://www.ascii-code.com/
# CHAR_SET = r"[^\x00-\xFF]"
# Temporary only check for chars in between 7f-9f, like in the old Feed-QA...
CHAR_SET = r"[\x7F-\x9F]"


def subprocess_cmd(command: str) -> bytes:
    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    proc_stdout = process.communicate()[0].strip()
    return proc_stdout


class CheckEncoding(LineContentPlugin):
    name = "check_encoding"

    def check_lines(
        self,
        nasl_file: Path,
        lines: Iterable[str],
    ) -> Iterator[LinterResult]:
        # Looking for VTs with wrong encoding... (maybe find a better way
        # to do this in future ...)
        encoding = subprocess_cmd(
            f"LC_ALL=C file {nasl_file} | grep 'UTF-8'"
        ).decode("latin-1")
        if len(encoding) > 0:
            yield LinterError(f"VT '{nasl_file}' has a wrong encoding.")

        for index, line in enumerate(lines):
            encoding = re.search(CHAR_SET, line)
            if encoding is not None:
                yield LinterError(f"Found invalid character in line {index}")

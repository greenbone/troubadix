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

import subprocess
import re
from pathlib import Path
from typing import Iterator

# import magic

from naslinter.plugin import FileContentPlugin, LinterError, LinterResult

# Only the ASCII and extended ASCII for now... # https://www.ascii-code.com/
# CHAR_SET = r"[^\x00-\xFF]"
# Temporary only check for chars in between 7f-9f, like in the old Feed-QA...
CHAR_SET = r"[\x7F-\x9F]"


def subprocess_cmd(command: str) -> bytes:
    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    proc_stdout = process.communicate()[0].strip()
    return proc_stdout


class CheckEncoding(FileContentPlugin):
    name = "check_encoding"

    @staticmethod
    def run(nasl_file: Path, file_content: str) -> Iterator[LinterResult]:
        # Looking for VTs with wrong encoding...
        # m = magic.Magic(mime_encoding=True)
        # encoding = m.from_buffer(file_content)
        # if not encoding == "latin-1" and not encoding == "us-ascii":
        #     yield LinterError(f"VT '{nasl_file}' has a wrong encoding.")

        # nb: The above code currently has some issues to detect the encoding so
        # it is currently temporary replaced by this function.
        encoding = subprocess_cmd(
            f"LC_ALL=C file {nasl_file} | grep 'UTF-8'"
        ).decode("latin-1")
        if len(encoding) > 0:
            yield LinterError(f"VT '{nasl_file}' has a wrong encoding.")

        # Checking characters line by line
        lines = file_content.splitlines()

        for index, line in enumerate(lines):
            encoding = re.search(CHAR_SET, line)
            if encoding is not None:
                yield LinterError(f"Found invalid character in line {index}")

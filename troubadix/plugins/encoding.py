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
from typing import Iterable, Iterator

import charset_normalizer

from troubadix.plugin import LineContentPlugin, LinterError, LinterResult

# Only the ASCII and extended ASCII for now... # https://www.ascii-code.com/
# CHAR_SET = r"[^\x00-\xFF]"
# Temporary only check for chars in between 7f-9f, like in the old Feed-QA...
INVALID_CHAR_PATTERN = re.compile(r"[\x7F-\x9F]")

ALLOWED_ENCODINGS = ["ascii", "latin_1"]


class CheckEncoding(LineContentPlugin):
    name = "check_encoding"

    def check_lines(
        self,
        nasl_file: Path,
        lines: Iterable[str],
    ) -> Iterator[LinterResult]:
        match = charset_normalizer.from_path(
            nasl_file, threshold=0.4, cp_isolation=ALLOWED_ENCODINGS
        ).best()

        if not match:
            yield LinterError(
                f"VT uses a wrong encoding. "
                f"Allowed encodings are {', '.join(ALLOWED_ENCODINGS)}.",
                file=nasl_file,
                plugin=self.name,
            )

        for index, line in enumerate(lines, 1):
            encoding = INVALID_CHAR_PATTERN.search(line)
            if encoding:
                yield LinterError(
                    f"Found invalid character in line: {index}",
                    file=nasl_file,
                    plugin=self.name,
                    line=index,
                )

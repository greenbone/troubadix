# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG

import re
from pathlib import Path
from typing import Iterable, Iterator

from troubadix.helper.patterns import (
    SpecialScriptTag,
    get_special_script_tag_pattern,
)
from troubadix.plugin import LineContentPlugin, LinterError, LinterResult

RE_PATTERN = re.compile(r"re\s*:")

MANDATORY_KEYS_PATTERN = get_special_script_tag_pattern(
    SpecialScriptTag.MANDATORY_KEYS
)


class CheckMultipleReParameters(LineContentPlugin):
    """This step checks if a VT
    has multiple mandatory_script_key re parameters
    """

    name = "check_multiple_re_parameters"

    def check_lines(
        self, nasl_file: Path, lines: Iterable[str]
    ) -> Iterator[LinterResult]:

        if self.context.nasl_file.suffix == ".inc":
            return

        re_pattern_count = 0
        for line in lines:
            if not (match := MANDATORY_KEYS_PATTERN.search(line)):
                continue
            if re.match(r"^\s*#", line):
                continue
            re_pattern_count += len(RE_PATTERN.findall(match.group("value")))

        if re_pattern_count > 1:
            yield LinterError(
                f"The re parameter of script_mandatory_keys can only "
                f"be defined once, but was found {re_pattern_count} times",
                file=nasl_file,
                plugin=self.name,
            )

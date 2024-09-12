# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG
import re
from collections.abc import Iterator
from operator import itemgetter
from pathlib import Path

from troubadix.helper import CURRENT_ENCODING
from troubadix.helper.patterns import (
    ScriptTag,
    get_script_tag_pattern,
)
from troubadix.plugin import (
    FileContentPlugin,
    LinterFix,
    LinterResult,
    LinterWarning,
)

TAGS = [
    ScriptTag.SUMMARY,
    ScriptTag.VULDETECT,
    ScriptTag.INSIGHT,
    ScriptTag.IMPACT,
    ScriptTag.AFFECTED,
    ScriptTag.SOLUTION,
]

# Regex pattern to match:
# 1. A dot preceded and/or followed by any whitespace character (floating between words)
# 2. A dot preceded by any whitespace character at the end of the string
PATTERN = re.compile(r"\s+\.(\s|$)")


class CheckSpacesBeforeDots(FileContentPlugin):
    name = "check_spaces_before_dots"

    def check_content(
        self, nasl_file: Path, file_content: str
    ) -> Iterator[LinterResult]:
        """
        This plugin checks for excess whitespace before a dot
        in script_tags that have full sentence values
        """
        self.matches = []
        if nasl_file.suffix == ".inc":
            return
        for tag in TAGS:
            pattern = get_script_tag_pattern(tag)
            match = pattern.search(file_content)
            if match:
                value = match.group("value")
                value_start = match.start("value")

                for excess_match in PATTERN.finditer(value):
                    whitespace_pos = excess_match.start() + value_start
                    self.matches.append((whitespace_pos, excess_match.group()))
                    fullmatch = match.group()
                    yield LinterWarning(
                        f"value of script_tag {match.group('name')} has alteast"
                        " one occurence of excess whitespace before a dot:"
                        f"\n '{fullmatch}'",
                        file=nasl_file,
                        plugin=self.name,
                    )

    def fix(self) -> Iterator[LinterResult]:

        if not self.matches:
            return

        # Sort matches by position, descending order to avoid messing up indices during replacement
        self.matches.sort(reverse=True, key=itemgetter(0))

        file_content = self.context.file_content
        for pos, match_str in self.matches:
            # Replace the match by removing the excess whitespace before the dot
            fixed_str = re.sub(r"\s+\.", ".", match_str)
            file_content = (
                file_content[:pos]
                + fixed_str
                + file_content[pos + len(match_str) :]
            )

        with open(self.context.nasl_file, "w", encoding=CURRENT_ENCODING) as f:
            f.write(file_content)

        yield LinterFix(
            "Excess spaces were removed",
            file=self.context.nasl_file,
            plugin=self.name,
        )

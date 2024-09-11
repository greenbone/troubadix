# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG
import re
from collections.abc import Iterator
from pathlib import Path

from troubadix.helper.patterns import (
    ScriptTag,
    get_script_tag_pattern,
)
from troubadix.plugin import FileContentPlugin, LinterResult, LinterWarning

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
PATTERN = re.compile(r"\s\.\s|\s\.$")


class CheckSpacesBeforeDots(FileContentPlugin):
    name = "check_spaces_before_dots"

    def check_content(
        self, nasl_file: Path, file_content: str
    ) -> Iterator[LinterResult]:
        """
        This plugin checks for excess whitespace before a dot
        in script_tags that have full sentence values
        """
        if nasl_file.suffix == ".inc":
            return
        for tag in TAGS:
            pattern = get_script_tag_pattern(tag)
            match = pattern.search(file_content)
            if match:
                value = match.group("value")
                if PATTERN.search(value):
                    fullmatch = match.group()
                    yield LinterWarning(
                        f"value of script_tag {match.group('name')} has alteast"
                        " one occurence of excess whitespace before a dot:"
                        f"\n '{fullmatch}'",
                        file=nasl_file,
                        plugin=self.name,
                    )

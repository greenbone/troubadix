# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG
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


class CheckSpacesBeforeDots(FileContentPlugin):
    name = "check_spaces_before_dots"

    def check_content(
        self, nasl_file: Path, file_content: str
    ) -> Iterator[LinterResult]:
        """
        This plugin checks for excess space before the dot
        in script_tags that have full sentence values
        """
        if nasl_file.suffix == ".inc":
            return
        for tag in TAGS:
            pattern = get_script_tag_pattern(tag)
            match = pattern.search(file_content)
            if match:
                s = match.group("value")
                # check if last char is a dot and second last a space
                if len(s) >= 2 and s[-1] == "." and s[-2] == " ":
                    fullmatch = match.group()
                    yield LinterWarning(
                        f"value of script_tag {match.group('name')} has"
                        f" a excess space before the dot:\n '{fullmatch}'",
                        file=nasl_file,
                        plugin=self.name,
                    )

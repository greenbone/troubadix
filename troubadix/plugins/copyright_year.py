# SPDX-FileCopyrightText: 2021 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import re
from pathlib import Path
from typing import Iterator

from troubadix.helper import is_ignore_file
from troubadix.helper.patterns import (
    ScriptTag,
    SpecialScriptTag,
    get_script_tag_pattern,
    get_special_script_tag_pattern,
)
from troubadix.plugin import (
    FileContentPlugin,
    LinterError,
    LinterResult,
)

_IGNORE_FILES = ()


SPDX_OR_COPYRIGHT_PATTERN = re.compile(
    r"(SPDX-FileCopyrightText:|Copyright \(C\))\s*(?P<year>\d{4})"
)


def _generate_header_lines(file_content: str):
    for line in file_content.splitlines():
        if line.startswith("#"):
            yield line
        else:
            break


class CheckCopyrightYear(FileContentPlugin):
    """This steps checks if a VT contains a Copyright statement containing a
    year not matching the year defined in the creation_date statement.

    pre2008 script copyright are allowed to predate the creation_year

    For scripts that contain multiple copyrights with different dates,
    like gather-package-list.nasl, it is important that the newer one,
    which is only valid as of a certain year, has information about
    what it covers in the place where the year would normally be.
    Then that line will be automatically ignored
    without having to add it to the ignore list due to not matching the regex.
    Example:
        if creation year = 2008
    ok:
    # SPDX-FileCopyrightText: 2008 Tim Brown
    # SPDX-FileCopyrightText: New detection methods / pattern / code since 2009 Greenbone AG
    not ok / needs ignore entry:
    # New NASL / detection code since 2018 Copyright (C) 2018 Greenbone AG

    """

    name = "check_copyright_year"

    def check_content(
        self, nasl_file: Path, file_content: str
    ) -> Iterator[LinterResult]:
        if nasl_file.suffix == ".inc" or is_ignore_file(
            nasl_file, _IGNORE_FILES
        ):
            return
        # extract creation year from script tag
        creation_date_pattern = get_script_tag_pattern(ScriptTag.CREATION_DATE)
        creation_date_match = creation_date_pattern.search(file_content)
        if not creation_date_match:
            yield LinterError(
                "Missing creation_date statement in VT",
                file=nasl_file,
                plugin=self.name,
            )
            return
        creation_year = int(creation_date_match.group("value")[:4])

        # extract year in value of script_copyright tag
        script_copyright_pattern = get_special_script_tag_pattern(
            SpecialScriptTag.COPYRIGHT
        )
        script_copyright_match = script_copyright_pattern.search(file_content)
        if not script_copyright_match:
            yield LinterError(
                "Missing copyright tag in VT",
                file=nasl_file,
                plugin=self.name,
            )
            return
        copyright_tag_value = script_copyright_match.group("value")
        copyright_tag_match = SPDX_OR_COPYRIGHT_PATTERN.search(
            copyright_tag_value
        )
        if not copyright_tag_match:
            yield LinterError(
                "Unable to extract year from script_copyright tag in VT",
                file=nasl_file,
                plugin=self.name,
            )
            return
        copyright_tag_year = int(copyright_tag_match.group("year"))

        # list comprehension to collect copy right matches from header
        header_lines = _generate_header_lines(file_content)
        header_copyright_years = [
            int(match.group("year"))
            for line in header_lines
            if (match := SPDX_OR_COPYRIGHT_PATTERN.search(line))
        ]

        if not header_copyright_years:
            yield LinterError(
                "VT header is missing a copyright text",
                file=nasl_file,
                plugin=self.name,
            )

        # check if the copyrights years match the creation year
        # pre2008 VTs are allowed to have a copyright that predates the year of creation.
        if copyright_tag_year != creation_year:
            if "pre2008" in str(nasl_file):
                if copyright_tag_year > creation_year:
                    yield LinterError(
                        "a pre2008 vt has a copyright tag year newer than the creation_year",
                        file=nasl_file,
                        plugin=self.name,
                    )
            else:
                yield LinterError(
                    "script_copyright tag does not match the creation year",
                    file=nasl_file,
                    plugin=self.name,
                )
        for copyright_year in header_copyright_years:
            if creation_year != copyright_year:
                if "pre2008" in str(nasl_file):
                    if copyright_year > creation_year:
                        yield LinterError(
                            "a pre2008 vt has a copyright value in the fileheader"
                            " newer than the creation_year",
                            file=nasl_file,
                            plugin=self.name,
                        )
                else:
                    yield LinterError(
                        "a copyright in the fileheader does not match the creation year",
                        file=nasl_file,
                        plugin=self.name,
                    )

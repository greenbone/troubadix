# SPDX-FileCopyrightText: 2022 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path
from typing import Iterator

from troubadix.helper import is_ignore_file
from troubadix.helper.patterns import get_script_tag_patterns

from ..plugin import FileContentPlugin, LinterError, LinterResult

# Arbitrary limit adopted from original step
VALUE_LIMIT = 3000

IGNORE_FILES = [
    # This has so many vulnerabilities, and we want at least mention each of them, so no way to
    # shorten it down.
    "monstra_cms_mult_vuln",
    # Same as previously
    "2017/gb_generic_http_web_app_params_dir_trav.nasl",
    "2017/gb_generic_http_web_root_dir_trav.nasl",
    "2021/gb_generic_http_web_dirs_dir_trav.nasl",
    # These have auto-generated affected tags which we don't want to shorten down.
    "gb_huawei-sa-",
    # Needs a description for each option which we don't want to shorten down.
    "lsc_options.nasl",
]


class CheckOverlongScriptTags(FileContentPlugin):
    """This steps checks if the script_tag summary, impact,
    affected, insight, vuldetect or solution of a given VT
    contains an overlong line within the value string.

    Background for this is that (e.g. auto generated LSCs)
    are created by parsing an advisory and the whole
    content is placed in such a tag which could be quite large.
    """

    name = "check_overlong_script_tags"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        if nasl_file.suffix == ".inc":
            return

        if is_ignore_file(nasl_file, IGNORE_FILES):
            return

        script_tag_patterns = get_script_tag_patterns()
        for tag, pattern in script_tag_patterns.items():
            for match in pattern.finditer(file_content):
                if len(match.group("value")) > VALUE_LIMIT:
                    yield LinterError(
                        f"Tag {tag.value} is to long"
                        f" with {len(match.group('value'))} characters. "
                        f"Max {VALUE_LIMIT}",
                        file=nasl_file,
                        plugin=self.name,
                    )

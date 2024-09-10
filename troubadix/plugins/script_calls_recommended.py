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
from typing import Iterator

from troubadix.helper.patterns import (
    _get_special_script_tag_pattern,
    _get_tag_pattern,
)
from troubadix.plugin import FileContentPlugin, LinterResult, LinterWarning


class CheckScriptCallsRecommended(FileContentPlugin):
    name = "check_script_calls_recommended"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """
        This script checks for the existence of recommended script calls. These
        are categorize int two groups. In group 2 it is recommended to call
        every single one. In group 1 it is sufficient to call one of the script
        calls.

        group1:
        - script_dependencies

        group2:
        - script_require_ports
        - script_require_udp_ports
        - script_require_keys
        - script_mandatory_keys
        """
        if (
            nasl_file.suffix == ".inc"
            or "# troubadix: disable=template_nd_test_files_fps" in file_content
        ):
            return

        if _get_special_script_tag_pattern(
            name=r"category", value=r"ACT_(SETTINGS|SCANNER|INIT)"
        ).search(file_content) or _get_tag_pattern(
            name=r"deprecated", value=r"TRUE"
        ).search(
            file_content
        ):
            return

        recommended_single_call = [r"dependencies"]
        recommended_many_call = [
            r"require_ports",
            r"require_udp_ports",
            r"require_keys",
            r"mandatory_keys",
        ]

        if not _get_special_script_tag_pattern(
            name=rf"({'|'.join(recommended_many_call)})",
            value=".*?",
            flags=re.DOTALL,
        ).search(file_content):
            yield LinterWarning(
                "VT contains none of the following recommended calls: "
                f"{', '.join(recommended_many_call)}",
                file=nasl_file,
                plugin=self.name,
            )
        for call in recommended_single_call:
            if not _get_special_script_tag_pattern(
                name=call, value=".*", flags=re.DOTALL
            ).search(file_content):
                yield LinterWarning(
                    "VT does not contain the following recommended call: "
                    f"'script_{call}'",
                    file=nasl_file,
                    plugin=self.name,
                )

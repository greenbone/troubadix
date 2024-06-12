#  Copyright (c) 2022 Greenbone AG
#
#  SPDX-License-Identifier: GPL-3.0-or-later
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
from pathlib import Path
from typing import Iterator

from troubadix.helper.patterns import ScriptTag, get_script_tag_pattern
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult

SECURITY_MESSAGE_IMPLEMENTATIONS = [
    "security_message",
    "http_check_remote_code",
    "citrix_xenserver_check_report_is_vulnerable",
    "citrix_xenserver_report_missing_patch",
]


def _file_contains_security_message(file_content: str) -> bool:
    """Checks wether a VT content contains a call to security_message
    or any function known to implement it

    Args:
        file_content (str): The content of the VT
    """
    return any(
        security_message in file_content
        for security_message in SECURITY_MESSAGE_IMPLEMENTATIONS
    )


class CheckSecurityMessages(FileContentPlugin):
    name = "check_security_messages"

    def _check_security_message_present(
        self, nasl_file: Path, file_content: str
    ) -> Iterator[LinterResult]:
        """Checks that the VT does have a
        security_message or implementing function call

        Args:
            nasl_file (Path): The VTs path
            file_content (str): The content of the VT
        """
        deprecated_pattern = get_script_tag_pattern(
            script_tag=ScriptTag.DEPRECATED
        )
        if deprecated_pattern.search(file_content):
            return

        if not _file_contains_security_message(file_content):
            yield LinterError(
                "VT is missing a security_message or implementing"
                " function in a VT with severity",
                file=nasl_file,
                plugin=self.name,
            )

    def _check_security_message_absent(
        self, nasl_file: Path, file_content: str
    ) -> Iterator[LinterResult]:
        """Checks that the VT does not have a
        security_message or implementing function call

        Args:
            nasl_file (Path): The VTs path
            file_content (str): The content of the VT
        """
        # Policy VTs might use both, security_message and log_message
        if "Policy/" in str(nasl_file) or "GSHB/" in str(nasl_file):
            return

        if _file_contains_security_message(file_content):
            yield LinterError(
                "VT is using a security_message or implementing"
                " function in a VT without severity",
                file=nasl_file,
                plugin=self.name,
            )

    def _determinate_security_message_by_severity(
        self, file_content: str
    ) -> bool:
        """Determinates wether a VT requires a
        security_message or implementing function
        call

        Args:
            file_content (str): The content of the VT
        """
        cvss_base_pattern = get_script_tag_pattern(ScriptTag.CVSS_BASE)
        cvss_detect = cvss_base_pattern.search(file_content)

        return cvss_detect and cvss_detect.group("value") != "0.0"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """This script checks the passed VT if it is using a security_message
        and having no severity (CVSS score) assigned or has a severity assigned
        but does not call security_message or an implementing function

        Args:
            nasl_file: The VT that is going to be checked
            file_content: The content of the VT

        """
        if nasl_file.suffix == ".inc":
            return

        security_message_required = (
            self._determinate_security_message_by_severity(file_content)
        )

        if security_message_required:
            yield from self._check_security_message_present(
                nasl_file, file_content
            )
        else:
            yield from self._check_security_message_absent(
                nasl_file, file_content
            )

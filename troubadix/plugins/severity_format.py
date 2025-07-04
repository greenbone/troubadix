# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

from pathlib import Path
from typing import Iterator

from troubadix.helper import ScriptTag, get_script_tag_pattern
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class CheckSeverityFormat(FileContentPlugin):
    name = "check_severity_format"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:

        if nasl_file.suffix == ".inc" or "severity_vector" not in file_content:
            return

        severity_vector_pattern = get_script_tag_pattern(
            ScriptTag.SEVERITY_VECTOR
        )

        severity_vector_match = severity_vector_pattern.search(file_content)
        if not severity_vector_match:
            yield LinterError(
                "VT has an invalid severity_vector value.",
                file=nasl_file,
                plugin=self.name,
            )

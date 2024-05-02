# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG

import re
from pathlib import Path
from typing import Iterator

from troubadix.plugin import FileContentPlugin, LinterError, LinterResult

pattern = re.compile(r"script_mandatory_keys.*re\s*:")


class CheckMultipleReParameters(FileContentPlugin):
    """This step checks if a VT
    has multiple mandatory_script_key re parameters
    """

    name = "check_multiple_re_parameters"

    def check_content(
        self, nasl_file: Path, file_content: str
    ) -> Iterator[LinterResult]:

        if self.context.nasl_file.suffix == ".inc":
            return

        matches = pattern.findall(file_content)
        if len(matches) > 1:
            yield LinterError(
                f"The re parameter of script_mandatory_keys can only "
                f"be defined 1 time, but was found {len(matches)} times",
                file=nasl_file,
                plugin=self.name,
            )

# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG

from typing import Iterator

from troubadix.plugin import FilePlugin, LinterError, LinterResult


class CheckSpacesInFilename(FilePlugin):
    name = "check_spaces_in_filename"

    def run(self) -> Iterator[LinterResult]:
        if " " in self.context.nasl_file.name:
            yield LinterError(
                f"The VT {self.context.nasl_file}"
                " contains spaces in the filename",
                file=self.context.nasl_file,
                plugin=self.name,
            )

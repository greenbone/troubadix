# Copyright (C) 2021 Greenbone Networks GmbH
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

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional

from troubadix.helper import CURRENT_ENCODING


@dataclass
class LinterResult:
    """A result found during running a check"""

    message: str
    file: Optional[Path] = None
    plugin: Optional[str] = None
    line: Optional[int] = None


class LinterWarning(LinterResult):
    """A result that is considered a warning"""


class LinterError(LinterResult):
    """A error found during a check"""


class LinterFix(LinterResult):
    """A fix that has been applied"""


class FilePluginContext:
    def __init__(
        self,
        *,
        root: Path,
        nasl_file: Path = None,
    ) -> None:
        self.root = root
        self.nasl_file = nasl_file

        self._file_content = None
        self._lines = None

    @property
    def file_content(self) -> str:
        if not self._file_content:
            self._file_content = self.nasl_file.read_text(
                encoding=CURRENT_ENCODING
            )
        return self._file_content

    @property
    def lines(self) -> Iterable[str]:
        if not self._lines:
            self._lines = self.file_content.splitlines()
        return self._lines


class FilesPluginContext:
    def __init__(self, *, root: Path, nasl_files: Iterable[Path]) -> None:
        self.root = root
        self.nasl_files = nasl_files


class Plugin(ABC):
    """A linter plugin"""

    name: str = None
    description: str = None

    @abstractmethod
    def run(self) -> Iterator[LinterResult]:
        pass

    def fix(self) -> Iterator[LinterResult]:
        return []


class FilesPlugin(Plugin):
    """A plugin that does checks over all files"""

    def __init__(self, context: FilesPluginContext) -> None:
        self.context = context


class FilePlugin(Plugin):
    """A plugin that does checks on single files"""

    def __init__(self, context: FilePluginContext) -> None:
        self.context = context


class FileContentPlugin(FilePlugin):
    """A plugin that does checks on the whole file content"""

    def run(self) -> Iterator[LinterResult]:
        return self.check_content(
            self.context.nasl_file, self.context.file_content
        )

    @abstractmethod
    def check_content(
        self, nasl_file: Path, file_content: str
    ) -> Iterator[LinterResult]:
        pass


class LineContentPlugin(FilePlugin):
    """A plugin that checks file content line by line"""

    def run(self) -> Iterator[LinterResult]:
        return self.check_lines(self.context.nasl_file, self.context.lines)

    @abstractmethod
    def check_lines(
        self,
        nasl_file: Path,
        lines: Iterable[str],
    ) -> Iterator[LinterResult]:
        pass

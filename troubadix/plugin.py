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
from typing import Iterable, Iterator


@dataclass
class LinterMessage:
    message: str


class LinterResult(LinterMessage):
    pass


class LinterWarning(LinterMessage):
    pass


class LinterError(LinterMessage):
    pass


class Plugin(ABC):
    """A linter plugin"""

    name: str = None
    description: str = None


class PreRunPlugin(Plugin):
    """A plugin that only runs PreRun collectors"""

    @staticmethod
    @abstractmethod
    def run(
        nasl_files: Iterable[Path],
    ) -> Iterator[LinterResult]:
        pass

    @staticmethod
    @abstractmethod
    def ok():
        pass


class FileContentPlugin(Plugin):
    """A plugin that does checks on the whole file content"""

    @staticmethod
    @abstractmethod
    def run(
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        pass


class LineContentPlugin(Plugin):
    """A plugin that checks file content line by line"""

    @staticmethod
    @abstractmethod
    def run(
        nasl_file: Path,
        lines: Iterable[str],
    ) -> Iterator[LinterResult]:
        pass

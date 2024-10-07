# Copyright (C) 2021 Greenbone AG
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
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

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
        nasl_file: Path,
    ) -> None:
        self.root = root
        self.nasl_file = nasl_file

        self._file_content: str | None = None
        self._lines: list[str] | None = None

    @property
    def file_content(self) -> str:
        if not self._file_content:
            self._file_content = self.nasl_file.read_text(
                encoding=CURRENT_ENCODING
            )
        return self._file_content

    @property
    def lines(self) -> list[str]:
        if not self._lines:
            self._lines = self.file_content.splitlines()
        return self._lines


class FilesPluginContext:
    def __init__(self, *, root: Path, nasl_files: Iterable[Path]) -> None:
        self.root = root
        self.nasl_files = nasl_files


class ConfigurationError(Exception):
    """Custom exception for plugin_configuration errors."""


class Plugin(ABC):
    """A linter plugin"""

    name: str

    # Value to indicate that a plugin depends on an external configuration
    require_external_config = False

    def __init__(self, config: dict) -> None:
        if self.require_external_config:
            self.config = self.extract_plugin_config(config)

    def extract_plugin_config(self, config: dict) -> dict:
        """
        extracts the configuration for a specific plugin
        from the entire configuration.

        Args:
            config (dict): The entire configuration dictionary.

        Returns:
            dict: The configuration dictionary for the specific plugin.

        Raises:
            ConfigurationError: If no configuration exists or validation fails.
        """
        if self.name not in config:
            raise ConfigurationError(
                f"Configuration for plugin '{self.name}' is missing."
            )
        plugin_config = config[self.name]
        self.validate_plugin_config(plugin_config)
        return plugin_config

    def validate_plugin_config(self, config: dict) -> None:
        """
        Validates the configuration for a specific plugin

        Not @abstract due to only being necessary
        if require_external_config is true

        Args:
            config (dict): The configuration dictionary for the specific plugin.

        Raises:
            ConfigurationError: If the plugins required keys are missing.
        """
        raise RuntimeError(
            f"{self.__class__.__name__} has not implemented method"
            " 'validate_and_extract_plugin_config'."
            " This method should be overridden in subclasses,"
            " if they require external config"
        )

    @abstractmethod
    def run(self) -> Iterator[LinterResult]:
        pass

    def fix(self) -> Iterator[LinterResult]:
        return iter([])


class FilesPlugin(Plugin):
    """A plugin that does checks over all files"""

    def __init__(self, context: FilesPluginContext, **kwargs) -> None:
        if "config" in kwargs:
            super().__init__(kwargs["config"])
        self.context = context


class FilePlugin(Plugin):
    """A plugin that does checks on single files"""

    def __init__(self, context: FilePluginContext, **kwargs) -> None:
        if "config" in kwargs:
            super().__init__(kwargs["config"])

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

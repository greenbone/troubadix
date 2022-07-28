# Copyright (C) 2022 Greenbone Networks GmbH
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

import tempfile
import unittest
from pathlib import Path
from typing import Iterable
from unittest.mock import MagicMock

from troubadix.plugin import FilePluginContext, FilesPluginContext


class TemporaryDirectory:
    """A wrapper around tempdir.TemporaryDirectory to return a Path
    when using the with statement
    """

    def __init__(self) -> None:
        self._tempdir = tempfile.TemporaryDirectory()

    def __enter__(self) -> Path:
        return Path(self._tempdir.__enter__())

    def __exit__(self, exc, value, tb) -> None:
        self._tempdir.__exit__(exc, value, tb)

    def __fspath__(self):
        return self._tempdir.name

    def cleanup(self):
        self._tempdir.cleanup()


class PluginTestCase(unittest.TestCase):
    def create_directory(self) -> TemporaryDirectory:
        return TemporaryDirectory()

    def create_file_plugin_context(
        self,
        *,
        nasl_file: Path = None,
        file_content: str = None,
        lines: Iterable[str] = None,
        root: Path = None,
    ) -> FilePluginContext:
        """Create a FilePluginContext mock"""
        fake_context = MagicMock()
        fake_context.nasl_file = nasl_file
        fake_context.file_content = file_content
        fake_context.lines = lines
        fake_context.root = root
        return fake_context

    def create_files_plugin_context(
        self,
        *,
        nasl_files: Iterable[Path] = None,
        root: Path = None,
    ) -> FilesPluginContext:
        """Create a FilePluginContext mock"""
        fake_context = MagicMock()
        fake_context.nasl_files = nasl_files
        fake_context.root = root
        return fake_context

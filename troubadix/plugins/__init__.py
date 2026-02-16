# Copyright (C) 2021-2022 Greenbone AG
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

"""
This package contains all linter plugins.
Plugins are discovered dynamically at runtime. To add a new plugin:
1. Create a new .py file in this directory.
2. Define a class that inherits from FilePlugin or FilesPlugin.

The discovery logic only searches the top-level of this package.
Nested sub-packages are currently not supported for plugin discovery.
To permanently disable a plugin, move it to a "disabled" subfolder.
"""

import difflib
import importlib
import pkgutil
from typing import Iterable, Type

from troubadix.plugin import FilePlugin, FilesPlugin, Plugin


def _get_all_subclasses(cls: Type) -> Iterable[Type]:
    """Recursively find all subclasses of a given class."""
    for subclass in cls.__subclasses__():
        yield from _get_all_subclasses(subclass)
        yield subclass


def _discover_plugins() -> tuple[list[Type[FilePlugin]], list[Type[FilesPlugin]]]:
    """
    Dynamically discover all concrete plugin classes.

        A tuple containing (list of file plugins, list of files plugins).
    """
    for _loader, module_name, _is_pkg in pkgutil.iter_modules(__path__):
        importlib.import_module(f"{__name__}.{module_name}")

    file_plugins = _get_all_subclasses(FilePlugin)
    files_plugins = _get_all_subclasses(FilesPlugin)

    return (
        sorted(file_plugins, key=lambda x: x.__name__),
        sorted(files_plugins, key=lambda x: x.__name__),
    )


_FILE_PLUGINS, _FILES_PLUGINS = _discover_plugins()


class Plugins:
    def __init__(
        self,
        file_plugins: Iterable[FilePlugin] = None,
        files_plugins: Iterable[FilesPlugin] = None,
    ):
        self.file_plugins = tuple(file_plugins) or tuple()
        self.files_plugins = tuple(files_plugins) or tuple()

    def __len__(self) -> int:
        return len(self.files_plugins + self.file_plugins)

    def __iter__(self) -> Iterable[Plugin]:
        return iter(self.files_plugins + self.file_plugins)


class StandardPlugins(Plugins):
    def __init__(
        self,
        excluded_plugins: list[str] = None,
        included_plugins: list[str] = None,
    ) -> None:
        file_plugins = _FILE_PLUGINS
        files_plugins = _FILES_PLUGINS

        if excluded_plugins:
            self._check_unknown_plugins(excluded_plugins)

            file_plugins = self._exclude_plugins(excluded_plugins, file_plugins)
            files_plugins = self._exclude_plugins(excluded_plugins, files_plugins)

        if included_plugins:
            self._check_unknown_plugins(included_plugins)

            file_plugins = self._include_plugins(included_plugins, file_plugins)
            files_plugins = self._include_plugins(included_plugins, files_plugins)

        super().__init__(file_plugins=file_plugins, files_plugins=files_plugins)

    @staticmethod
    def _exclude_plugins(excluded: Iterable[str], plugins: Iterable[Plugin]) -> list[Plugin]:
        return [
            plugin
            for plugin in plugins
            if plugin.__name__ not in excluded and plugin.name not in excluded
        ]

    @staticmethod
    def _include_plugins(included: Iterable[str], plugins: Iterable[Plugin]) -> list[Plugin]:
        return [
            plugin for plugin in plugins if plugin.__name__ in included or plugin.name in included
        ]

    @staticmethod
    def _check_unknown_plugins(selected_plugins: list[str]):
        all_plugin_names = {
            name
            for plugin in _FILE_PLUGINS + _FILES_PLUGINS
            for name in (plugin.name, plugin.__name__)
        }

        unknown_plugins = set(selected_plugins).difference(all_plugin_names)

        if not unknown_plugins:
            return

        def build_message(plugin: str):
            match = difflib.get_close_matches(plugin, all_plugin_names, n=1)
            return f"'{plugin}' (Did you mean '{match[0]}'?)" if match else f"'{plugin}'"

        messages = [build_message(plugin) for plugin in sorted(unknown_plugins)]
        raise ValueError(f"Unknown plugins: {', '.join(messages)}")

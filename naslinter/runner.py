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

from pathlib import Path
from typing import Iterable, List

from pontos.terminal.terminal import Terminal

from naslinter.plugin import (
    FileContentPlugin,
    LineContentPlugin,
    LinterError,
    LinterMessage,
    LinterResult,
    LinterWarning,
)
from naslinter.plugins import Plugins

CURRENT_ENCODING = "latin1"


class Runner:
    def __init__(
        self,
        excluded_plugins: List[str] = None,
        included_plugins: List[str] = None,
        terminal: Terminal = None,
    ) -> None:
        self.plugins = Plugins(excluded_plugins, included_plugins)
        self._term = terminal or Terminal()

    def _report_results(self, results: Iterable[LinterMessage]):
        for result in results:
            if isinstance(result, LinterResult):
                self._report_ok(result.message)
            elif isinstance(result, LinterError):
                self._report_error(result.message)
            elif isinstance(result, LinterWarning):
                self._report_warning(result.message)

    def _report_warning(self, message: str):
        self._term.warning(message)

    def _report_error(self, message: str):
        self._term.error(message)

    def _report_info(self, message: str):
        self._term.info(message)

    def _report_ok(self, message: str):
        self._term.ok(message)

    def run(
        self,
        files: Iterable[Path],
    ) -> None:

        for file_path in files:
            file_name = file_path.absolute()
            self._report_info(f"Checking {file_name}")

            with self._term.indent():
                if not file_path.exists():
                    self._report_warning("File does not exist.")
                    continue
                # some scripts are not executed on include (.inc) files
                if file_path.suffix != ".nasl" and file_path.suffix != ".inc":
                    self._report_warning("Not a NASL file.")
                    continue

                file_content = file_path.read_text(encoding=CURRENT_ENCODING)

                for plugin in self.plugins:
                    self._report_info(f"Running plugin {plugin.name}")
                    with self._term.indent():
                        if issubclass(plugin, LineContentPlugin):
                            lines = file_content.split("\n")
                            results = plugin.run(file_name, lines)
                        elif issubclass(plugin, FileContentPlugin):
                            results = plugin.run(file_name, file_content)
                        else:
                            self._report_error(
                                f"Plugin {plugin.__name__} can not be read."
                            )

                        self._report_results(results)

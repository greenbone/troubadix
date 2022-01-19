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

from naslinter.plugin import LineContentPlugin, LinterResult
from naslinter.plugins import Plugins

CURRENT_ENCODING = "latin1"


class Runner:
    def __init__(self, terminal: Terminal = None) -> None:
        self._term = terminal or Terminal()

    def _report_results(self, results: Iterable[LinterResult]):
        for result in results:
            self._report_error(result.message)

    def _report_warning(self, message: str):
        self._term.warning(message)

    def _report_error(self, message: str):
        self._term.error(message)

    def _report_info(self, message: str):
        self._term.info(message)

    def run(
        self,
        files: Iterable[Path],
        excluded_plugins: List[str] = None,
        included_plugins: List[str] = None,
    ) -> None:
        plugins = Plugins()
        for file_path in files:
            file_name = file_path.absolute()
            self._report_info(f"Checking {file_name}")

            with self._term.indent():
                if not file_path.exists():
                    self._report_warning("File does not exist.")
                    continue
                # some scripts are not executed on include (.inc) files
                if file_path.suffix != ".nasl" or file_path.suffix != ".inc":
                    self._report_warning("Not a NASL file.")
                    continue

                file_content = file_path.read_text(encoding=CURRENT_ENCODING)

                for plugin in plugins:
                    self._report_info(f"Running plugin {plugin.name}")
                    with self._term.indent():
                        if issubclass(plugin, LineContentPlugin):
                            lines = file_content.split("\n")
                            results = plugin.run(file_name, lines)
                        else:
                            results = plugin.run(file_name, file_content)

                        self._report_results(results)

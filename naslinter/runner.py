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

import datetime

from collections import OrderedDict
from multiprocessing import Pool
from pathlib import Path
from typing import Iterator, List

from pontos.terminal.terminal import Terminal

from naslinter.plugin import (
    FileContentPlugin,
    LineContentPlugin,
    LinterError,
    LinterMessage,
    LinterResult,
    LinterWarning,
    Plugin,
)
from naslinter.plugins import Plugins

CHUNKSIZE = 1  # default 1
CURRENT_ENCODING = "latin1"


class PluginResults:
    def __init__(self, plugin_name: str):
        self.plugin_name = plugin_name
        self.plugin_results = OrderedDict()
        self.generic_results = []

    def add_generic_result(self, result: LinterResult) -> "PluginResults":
        self.generic_results.append(result)
        return self

    def add_plugin_results(
        self, file_name: str, results: Iterator[LinterResult]
    ) -> "PluginResults":
        self.plugin_results[file_name] = list(results)
        return self


class Runner:
    def __init__(
        self,
        n_jobs: int,
        term: Terminal,
        *,
        excluded_plugins: List[str] = None,
        included_plugins: List[str] = None,
        debug: bool = False,
    ) -> None:
        self.plugins = Plugins(excluded_plugins, included_plugins)
        self._term = term
        self._n_jobs = n_jobs
        self.debug = debug

    def _report_results(self, results: List[LinterMessage]):
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

    def _report_bold_info(self, message: str):
        self._term.bold_info(message)

    def _report_ok(self, message: str):
        self._term.ok(message)

    def run(
        self,
        files: List[Path],
    ) -> None:
        self.files = files
        # files_count = len(files)
        # i = 0
        start = datetime.datetime.now()

        with Pool(processes=self._n_jobs) as pool:
            for results in pool.imap_unordered(
                self.run_plugin, self.plugins.__iter__(), chunksize=CHUNKSIZE
            ):
                self._report_bold_info(
                    "Checking " f"{str(results.plugin_name)}"
                )

                with self._term.indent():
                    self._report_results(results.generic_results)

                    for (
                        file_name,
                        plugin_results,
                    ) in results.plugin_results.items():
                        if plugin_results or self.debug:
                            file_str = str(file_name).split(
                                "nasl/", maxsplit=1
                            )[-1]
                            self._report_info(f"Found in {file_str}")
                        with self._term.indent():
                            self._report_results(plugin_results)

        self._report_info(f"Time elapsed: {datetime.datetime.now() - start}")

    def run_plugin(self, plugin: Plugin) -> PluginResults:
        results = PluginResults(plugin.name)
        start = datetime.datetime.now()
        for file_path in self.files:
            file_name = file_path.resolve()

            # maybe we need to re-read filecontent, if an Plugin changes it
            file_content = file_path.read_text(encoding=CURRENT_ENCODING)

            if issubclass(plugin, LineContentPlugin):
                lines = file_content.splitlines()
                results.add_plugin_results(
                    file_path, plugin.run(file_name, lines)
                )
            elif issubclass(plugin, FileContentPlugin):
                results.add_plugin_results(
                    file_path, plugin.run(file_name, file_content)
                )
            else:
                results.add_plugin_results(
                    file_path,
                    [LinterError(f"Plugin {plugin.__name__} can not be read.")],
                )
        self._report_info(f"Time elapsed: {datetime.datetime.now() - start}")
        return results

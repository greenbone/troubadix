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
from typing import Iterable, Iterator, List

from pontos.terminal.terminal import Terminal
from pontos.terminal import info

from naslinter.plugin import (
    FileContentPlugin,
    GitCommitRangePlugin,
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


class FileResults:
    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.plugin_results = OrderedDict()
        self.generic_results = []

    def add_generic_result(self, result: LinterResult) -> "FileResults":
        self.generic_results.append(result)
        return self

    def add_plugin_results(
        self, plugin: Plugin, results: Iterator[LinterResult]
    ) -> "FileResults":
        self.plugin_results[plugin.name] = list(results)
        return self


class Runner:
    def __init__(
        self,
        n_jobs: int,
        term: Terminal,
        excluded_plugins: List[str] = None,
        included_plugins: List[str] = None,
        commit_range: List[str] = None,
    ) -> None:
        self.plugins = Plugins(excluded_plugins, included_plugins)
        self._term = term
        self._n_jobs = n_jobs
        self._commit_range = commit_range

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
        files_list = list(files)

        start = datetime.datetime.now()
        with Pool(processes=self._n_jobs) as pool:
            for results in pool.imap_unordered(
                self.check_file, files_list, chunksize=CHUNKSIZE
            ):
                self._report_info(f"Checking {results.file_path}")

                with self._term.indent():
                    self._report_results(results.generic_results)

                    for (
                        plugin_name,
                        plugin_results,
                    ) in results.plugin_results.items():
                        self._report_info(f"Running plugin {plugin_name}")

                        with self._term.indent():
                            self._report_results(plugin_results)

                # add newline
                print()

        info(f"Time elapsed: {datetime.datetime.now() - start}")

    def check_file(self, file_path: Path) -> FileResults:
        file_name = file_path.resolve()
        results = FileResults(file_path)

        if not file_path.exists():
            return results.add_generic_result(
                LinterWarning(f"{file_path} does not exist.")
            )

        # some scripts are not executed on include (.inc) files
        if file_path.suffix != ".nasl" and file_path.suffix != ".inc":
            return results.add_generic_result(
                LinterWarning(f"{file_path} is not a NASL file.")
            )

        # maybe we need to re-read file-content, if a Plugin changes it
        file_content = file_path.read_text(encoding=CURRENT_ENCODING)

        for plugin in self.plugins:
            if issubclass(plugin, LineContentPlugin):
                lines = file_content.splitlines()
                results.add_plugin_results(plugin, plugin.run(file_name, lines))
            elif issubclass(plugin, FileContentPlugin):
                results.add_plugin_results(
                    plugin, plugin.run(file_name, file_content)
                )
            elif issubclass(plugin, GitCommitRangePlugin):
                results.add_plugin_results(
                    plugin, plugin.run(file_name, self._commit_range)
                )
            else:
                results.add_plugin_results(
                    plugin,
                    [LinterError(f"Plugin {plugin.__name__} can not be read.")],
                )

        return results

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
import signal

from collections import OrderedDict, defaultdict
from multiprocessing import Pool
from pathlib import Path
from typing import Dict, Iterator, List

from pontos.terminal.terminal import Terminal

from troubadix.helper.patterns import (
    init_script_tag_patterns,
    init_special_script_tag_patterns,
)
from troubadix.plugin import (
    FileContentPlugin,
    LineContentPlugin,
    LinterError,
    LinterMessage,
    LinterResult,
    LinterWarning,
)
from troubadix.plugins import Plugins

CHUNKSIZE = 1  # default 1
# js: can we get this to utf-8 in future @scanner @feed?
CURRENT_ENCODING = "latin1"  # currently default


class TroubadixException(Exception):
    """Generic Exception for Troubadix"""


def initializer():
    """Ignore CTRL+C in the worker process."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)


class FileResults:
    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.plugin_results = OrderedDict()
        self.generic_results = []

    def add_generic_result(self, result: LinterResult) -> "FileResults":
        self.generic_results.append(result)
        return self

    def add_plugin_results(
        self, plugin_name: str, results: Iterator[LinterResult]
    ) -> "FileResults":
        self.plugin_results[plugin_name] = list(results)
        return self


class ResultCounts:
    def __init__(self):
        self.result_counts = defaultdict(int)

    def add_result_counts(self, plugin: str, count: int):
        """Add the number of results (count) to the dict for the
        plugin name (plugin)"""
        if count > 1:
            self.result_counts[plugin] += count


class Runner:
    def __init__(
        self,
        n_jobs: int,
        term: Terminal,
        *,
        excluded_plugins: List[str] = None,
        included_plugins: List[str] = None,
        update_date: bool = False,
        verbose: int = 0,
        statistic: bool = True,
        log_file: Path = None,
    ) -> None:
        self.plugins = Plugins(
            excluded_plugins, included_plugins, update_date=update_date
        )
        self._excluded_plugins = excluded_plugins
        self._included_plugins = included_plugins
        self._term = term
        self._n_jobs = n_jobs
        self.verbose = verbose

        # this dict will store the result counts for the statistic
        self.result_counts = ResultCounts()
        self.statistic = statistic

        init_script_tag_patterns()
        init_special_script_tag_patterns()
        self._log_file = log_file

    def _log_append(self, message: str):
        if self._log_file:
            with self._log_file.open(mode="a", encoding="utf-8") as f:
                f.write(f"{message}\n")

    def _report_results(self, results: List[LinterMessage]) -> None:
        for result in results:
            if isinstance(result, LinterResult):
                self._report_ok(result.message)
            elif isinstance(result, LinterError):
                self._report_error(result.message)
            elif isinstance(result, LinterWarning):
                self._report_warning(result.message)

    def _report_warning(self, message: str) -> None:
        self._term.warning(message)
        self._log_append(f"\t\t{message}".replace("\n", "\n\t\t"))

    def _report_error(self, message: str) -> None:
        self._term.error(message)
        self._log_append(f"\t\t{message}".replace("\n", "\n\t\t"))

    def _report_info(self, message: str) -> None:
        self._term.info(message)
        self._log_append(f"\t{message}")

    def _report_bold_info(self, message: str) -> None:
        self._term.bold_info(message)
        self._log_append(f"\n\n{message}")

    def _report_ok(self, message: str) -> None:
        self._term.ok(message)
        self._log_append(f"\t\t{message}".replace("\n", "\n\t\t"))

    def _process_plugin_results(
        self, results: Dict[str, List[LinterMessage]]
    ) -> None:
        # print the files plugin results
        for (
            plugin_name,
            plugin_results,
        ) in results.items():
            if plugin_results and self.verbose > 0:
                self._report_info(f"Results for plugin {plugin_name}")
            elif self.verbose > 1:
                self._report_ok(f"No results for plugin {plugin_name}")

            # add the results to the statistic
            self.result_counts.add_result_counts(
                plugin_name, len(plugin_results)
            )

            if self.verbose > 0:
                with self._term.indent():
                    self._report_results(plugin_results)

    def _report_plugins(self) -> None:
        if self._excluded_plugins:
            exclude = ", ".join(self._excluded_plugins)
            self._report_info(f"Excluded Plugins: {exclude}")

        if self._included_plugins:
            include = ", ".join(self._included_plugins)
            self._report_info(f"Included Plugins: {include}")

        plugins = ", ".join([plugin.name for plugin in self.plugins.plugins])
        self._report_info(f"Running plugins: {plugins}")

    def _report_statistic(self) -> None:
        overall = 0
        self._term.print(f"{'Plugin':50} {'Error Count':11}")
        self._term.print("-" * 62)
        for (plugin, count) in self.result_counts.result_counts.items():
            overall += count
            self._term.error(f"{plugin:50} {count:11}")
        self._term.print("-" * 62)
        self._term.error(f"{'sum':50} {overall:11}")

    def run(
        self,
        files: List[Path],
    ) -> None:
        files_count = len(files)
        i = 0

        if not len(self.plugins):
            raise TroubadixException("No Plugin found.")

        if self.verbose > 1:
            self._report_plugins()

        start = datetime.datetime.now()
        with Pool(processes=self._n_jobs, initializer=initializer) as pool:
            try:
                for results in pool.imap_unordered(
                    self.check_file, files, chunksize=CHUNKSIZE
                ):
                    # only print the part "common/some_nasl.nasl" by
                    # splitting at the nasl/ dir in
                    # /root/vts-repo/nasl/common/some_nasl.nasl
                    short_file_name = str(results.file_path).split(
                        "nasl/", maxsplit=1
                    )[-1]
                    if self.verbose > 0:
                        self._report_bold_info(
                            f"Checking {short_file_name} ({i}/{files_count})"
                        )
                    i = i + 1

                    with self._term.indent():
                        if self.verbose > 0:
                            self._report_results(results.generic_results)
                        self._process_plugin_results(results.plugin_results)
            except KeyboardInterrupt:
                pool.terminate()
                pool.join()

        self._report_info(f"Time elapsed: {datetime.datetime.now() - start}")
        if self.statistic:
            self._report_statistic()

    def check_file(self, file_path: Path) -> FileResults:
        file_name = file_path.resolve()
        results = FileResults(file_path)

        # maybe we need to re-read filecontent, if an Plugin changes it
        file_content = file_path.read_text(encoding=CURRENT_ENCODING)

        for plugin in self.plugins:
            if issubclass(plugin, LineContentPlugin):
                lines = file_content.splitlines()
                results.add_plugin_results(
                    plugin.name,
                    plugin.run(
                        file_name,
                        lines,
                    ),
                )
            elif issubclass(plugin, FileContentPlugin):
                results.add_plugin_results(
                    plugin.name,
                    plugin.run(
                        file_name,
                        file_content,
                    ),
                )
            else:
                results.add_plugin_results(
                    plugin.__name__,
                    [LinterError(f"Plugin {plugin.__name__} can not be read.")],
                )

        return results

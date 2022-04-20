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
from typing import Dict, Iterable, Iterator

from pontos.terminal.terminal import Terminal
from troubadix.helper.helper import get_path_from_root

from troubadix.helper.patterns import (
    init_script_tag_patterns,
    init_special_script_tag_patterns,
)
from troubadix.plugin import (
    FilesPluginContext,
    LinterError,
    LinterMessage,
    LinterResult,
    LinterWarning,
    FilePluginContext,
    FilesPlugin,
)
from troubadix.plugins import (
    _PRE_RUN_PLUGINS,
    Plugins,
    StandardPlugins,
    UpdatePlugins,
)

CHUNKSIZE = 1  # default 1


class TroubadixException(Exception):
    """Generic Exception for Troubadix"""


def initializer():
    """Ignore CTRL+C in the worker process."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)


class FileResults:
    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.plugin_results: Dict[str, Iterable[LinterResult]] = OrderedDict()
        self.generic_results: Iterable[LinterResult] = []
        self.has_plugin_results = False

    def add_generic_result(self, result: LinterResult) -> "FileResults":
        self.generic_results.append(result)
        return self

    def add_plugin_results(
        self, plugin_name: str, results: Iterator[LinterResult]
    ) -> "FileResults":
        results = list(results)
        self.has_plugin_results = self.has_plugin_results or bool(results)
        self.plugin_results[plugin_name] = results
        return self

    def __bool__(self):
        return self.has_plugin_results


class ResultCounts:
    def __init__(self):
        self.result_counts = defaultdict(int)
        self.error_count = 0
        self.warning_count = 0

    def add_result_counts(self, plugin: str, count: int):
        """Add the number of results (count) to the dict for the
        plugin name (plugin)"""
        if count > 0:
            self.result_counts[plugin] += count

    def add_error(self):
        self.error_count += 1

    def add_warning(self):
        self.warning_count += 1


class Runner:
    def __init__(
        self,
        n_jobs: int,
        term: Terminal,
        *,
        root: Path,
        excluded_plugins: Iterable[str] = None,
        included_plugins: Iterable[str] = None,
        update_date: bool = False,
        verbose: int = 0,
        statistic: bool = True,
        log_file: Path = None,
    ) -> bool:
        # plugins initialization
        self.plugins: Plugins = (
            UpdatePlugins()
            if update_date
            else StandardPlugins(excluded_plugins, included_plugins)
        )
        self._excluded_plugins = excluded_plugins
        self._included_plugins = included_plugins

        self.pre_run_plugins = _PRE_RUN_PLUGINS

        self._term = term
        self._n_jobs = n_jobs
        self._log_file = log_file
        self._root = root
        self.verbose = verbose

        # this dict will store the result counts for the statistic
        self.result_counts = ResultCounts()
        self.statistic = statistic

        init_script_tag_patterns()
        init_special_script_tag_patterns()

    def _log_append(self, message: str):
        if self._log_file:
            with self._log_file.open(mode="a", encoding="utf-8") as f:
                f.write(f"{message}\n")

    def _report_results(self, results: Iterable[LinterMessage]) -> None:
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

    def _report_plugins(self) -> None:
        if self.pre_run_plugins:
            pre_run = ", ".join(
                [plugin.name for plugin in self.pre_run_plugins]
            )
            self._report_info(f"Pre-Run Plugins: {pre_run}")

        if self._excluded_plugins:
            exclude = ", ".join(self._excluded_plugins)
            self._report_info(f"Excluded Plugins: {exclude}")

        if self._included_plugins:
            include = ", ".join(self._included_plugins)
            self._report_info(f"Included Plugins: {include}")

        plugins = ", ".join([plugin.name for plugin in self.plugins])
        self._report_info(f"Running plugins: {plugins}")

    def _report_statistic(self) -> None:
        self._term.print(f"{'Plugin':50} {'Error Count':11}")
        self._term.print("-" * 62)

        for (plugin, count) in self.result_counts.result_counts.items():
            self._term.error(f"{plugin:50} {count:11}")

        self._term.print("-" * 62)
        self._term.error(f"{'warn':50} {self.result_counts.warning_count:11}")
        self._term.error(f"{'err':50} {self.result_counts.error_count:11}")

        counts = (
            self.result_counts.error_count + self.result_counts.warning_count
        )

        self._term.info(f"{'sum':50} {counts:11}")

    def _process_plugin_results(
        self, plugin_name: str, plugin_results: Iterable[LinterResult]
    ):
        if plugin_results and self.verbose > 0:
            self._report_info(f"Results for plugin {plugin_name}")
        elif self.verbose > 2:
            self._report_ok(f"No results for plugin {plugin_name}")

        # add the results to the statistic
        self.result_counts.add_result_counts(plugin_name, len(plugin_results))
        # Count errors
        for plugin_result in plugin_results:
            if isinstance(plugin_result, LinterError):
                self.result_counts.add_error()
            elif isinstance(plugin_result, LinterWarning):
                self.result_counts.add_warning()

        if self.verbose > 0:
            with self._term.indent():
                self._report_results(plugin_results)

    def _process_file_results(
        self,
        results: FileResults,
    ) -> None:
        if self.verbose > 0:
            self._report_results(results.generic_results)

        # print the files plugin results
        for (
            plugin_name,
            plugin_results,
        ) in results.plugin_results.items():
            self._process_plugin_results(plugin_name, plugin_results)

    def pre_run(self, nasl_files: Iterable[Path]) -> None:
        """Running Plugins that do not require a run per file,
        but a single execution"""
        context = FilesPluginContext(root=self._root, nasl_files=nasl_files)
        for plugin_class in self.pre_run_plugins:
            if not issubclass(plugin_class, FilesPlugin):
                self._report_error(
                    f"Plugin {plugin_class.name} can not be read."
                )
                continue

            plugin = plugin_class(context)

            results = list(plugin.run())

            with self._term.indent():
                if results and self.verbose > 0 or self.verbose > 1:
                    self._report_bold_info(f"Run plugin {plugin.name}")

                self._process_plugin_results(plugin.name, results)

    def run(self, files: Iterable[Path]) -> bool:
        if not len(self.plugins):
            raise TroubadixException("No Plugin found.")

        # print plugins that will be executed
        if self.verbose > 2:
            self._report_plugins()

        # statistic variables
        files_count = len(files)
        start = datetime.datetime.now()

        # run single time execution plugins
        self.pre_run(files)

        with Pool(processes=self._n_jobs, initializer=initializer) as pool:
            try:
                for i, results in enumerate(
                    pool.imap_unordered(
                        self.check_file, files, chunksize=CHUNKSIZE
                    )
                ):
                    if results and self.verbose > 0 or self.verbose > 1:
                        # only print the part "common/some_nasl.nasl"
                        from_root_path = get_path_from_root(
                            results.file_path, self._root
                        )
                        self._report_bold_info(
                            f"Checking {from_root_path} ({i}/{files_count})"
                        )

                    with self._term.indent():
                        self._process_file_results(results)

            except KeyboardInterrupt:
                pool.terminate()
                pool.join()

        self._report_info(f"Time elapsed: {datetime.datetime.now() - start}")
        if self.statistic:
            self._report_statistic()

        # Return true if error exist
        return self.result_counts.error_count > 0

    def check_file(self, file_path: Path) -> FileResults:
        results = FileResults(file_path)
        context = FilePluginContext(
            root=self._root, nasl_file=file_path.resolve()
        )

        for plugin_class in self.plugins:
            plugin = plugin_class(context)
            results.add_plugin_results(
                plugin.name,
                plugin.run(),
            )

        return results

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
from multiprocessing import Pool, Manager
from pathlib import Path
from typing import Dict, Iterator, List

from pontos.terminal.terminal import Terminal
from troubadix.helper.helper import get_path_from_root

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
    PreRunPlugin,
)
from troubadix.plugins import _PRE_RUN_PLUGINS, Plugins

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
        self.has_results = False

    def add_generic_result(self, result: LinterResult) -> "FileResults":
        self.generic_results.append(result)
        return self

    def add_plugin_results(
        self, plugin_name: str, results: Iterator[LinterResult]
    ) -> "FileResults":
        results = list(results)
        if results:
            self.has_results = True
        self.plugin_results[plugin_name] = results
        return self

    def __bool__(self):
        return self.has_results


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
        excluded_plugins: List[str] = None,
        included_plugins: List[str] = None,
        update_date: bool = False,
        verbose: int = 0,
        statistic: bool = True,
        log_file: Path = None,
    ) -> bool:
        # plugins initialization
        self.plugins = Plugins(
            excluded_plugins, included_plugins, update_date=update_date
        )
        self._excluded_plugins = excluded_plugins
        self._included_plugins = included_plugins

        self.mt_manager = Manager()
        self.pre_run_plugins = _PRE_RUN_PLUGINS
        self.pre_run_data = self.mt_manager.dict()

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

    def __getstate__(self):
        """called when pickling - this hack allows subprocesses to
        be spawned without the AuthenticationString raising an error"""
        state = self.__dict__.copy()
        if "mt_manager" in state:
            del state["mt_manager"]
        return state

    def __setstate__(self, state):
        """for unpickling"""
        self.__dict__.update(state)

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
            elif self.verbose > 2:
                self._report_ok(f"No results for plugin {plugin_name}")

            # add the results to the statistic
            self.result_counts.add_result_counts(
                plugin_name, len(plugin_results)
            )
            # Count errors
            for plugin_result in plugin_results:
                if isinstance(plugin_result, LinterError):
                    self.result_counts.add_error()
                elif isinstance(plugin_result, LinterWarning):
                    self.result_counts.add_warning()

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

    def pre_run(self, nasl_files: List[Path]) -> None:
        """Running Plugins that do not require a run per file,
        but a single execution"""
        # self._report_info("Starting pre-run")
        # self._report_info("Loading plugins")

        for plugin in self.pre_run_plugins:
            if issubclass(plugin, PreRunPlugin):
                results = list(
                    plugin.run(
                        nasl_files,
                    )
                )
                with self._term.indent():
                    if results and self.verbose > 0:
                        self._report_bold_info(f"Run plugin {plugin.name}")
                        for result in results:
                            self._report_error(message=result.message)
                    else:
                        if self.verbose > 2:
                            self._report_ok(plugin.ok())
            else:
                self._report_error(f"Plugin {plugin.__name__} can not be read.")

    def run(self, files: List[Path]) -> None:
        if not len(self.plugins):
            raise TroubadixException("No Plugin found.")

        # statistic variables
        files_count = len(files)
        i = 0
        start = datetime.datetime.now()

        # print plugins that will be executed
        if self.verbose > 2:
            self._report_plugins()

        # run single time execution plugins
        self.pre_run(files)

        start = datetime.datetime.now()
        with Pool(processes=self._n_jobs, initializer=initializer) as pool:
            try:
                for results in pool.imap_unordered(
                    self.check_file, files, chunksize=CHUNKSIZE
                ):
                    # only print the part "common/some_nasl.nasl" by
                    # splitting at the nasl/ dir in
                    # /root/vts-repo/nasl/common/some_nasl.nasl
                    if results and self.verbose > 0 or self.verbose > 1:
                        self._report_bold_info(
                            f"Checking {get_path_from_root(results.file_path)}"
                            f" ({i}/{files_count})"
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
        # Return true if error exist
        return self.result_counts.error_count > 0

    def check_file(self, file_path: Path) -> FileResults:
        file_name = file_path.resolve()
        results = FileResults(file_path)

        # maybe we need to re-read file content, if a Plugin changes it
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

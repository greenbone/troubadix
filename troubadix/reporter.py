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

from pathlib import Path
from typing import Iterable, List

from pontos.terminal.terminal import Terminal

from troubadix.helper.helper import get_path_from_root
from troubadix.plugin import (
    FilesPlugin,
    LinterError,
    LinterFix,
    LinterResult,
    LinterWarning,
)
from troubadix.plugins import Plugins
from troubadix.results import FileResults, ResultCounts


class Reporter:
    def __init__(
        self,
        term: Terminal,
        root: Path,
        *,
        fix: bool = False,
        log_file: Path = None,
        statistic: bool = True,
        verbose: int = 0,
    ) -> None:
        self._term = term
        self._log_file = log_file
        self._statistic = statistic
        self._verbose = verbose
        self._fix = fix
        self._files_count = 0
        self._root = root

        self._result_counts = ResultCounts()

    def set_files_count(self, count: int):
        self._files_count = count

    def get_error_count(self) -> int:
        return self._result_counts.error_count

    def _report_warning(self, message: str) -> None:
        self._term.warning(message)
        self._log_append(f"\t\t{message}".replace("\n", "\n\t\t"))

    def _report_error(self, message: str) -> None:
        self._term.error(message)
        self._log_append(f"\t\t{message}".replace("\n", "\n\t\t"))

    def report_info(self, message: str) -> None:
        """Report an info message"""
        self._term.info(message)
        self._log_append(f"\t{message}")

    def _report_bold_info(self, message: str) -> None:
        self._term.bold_info(message)
        self._log_append(f"\n\n{message}")

    def _report_ok(self, message: str) -> None:
        self._term.ok(message)
        self._log_append(f"\t\t{message}".replace("\n", "\n\t\t"))

    def _process_plugin_results(
        self, plugin_name: str, plugin_results: List[LinterResult]
    ):
        """Process the results of a plugin: Print/Log results if
        verbosity/logging fits and count the results"""
        if plugin_results and self._verbose > 0:
            self.report_info(f"Results for plugin {plugin_name}")
        elif self._verbose > 2:
            self._report_ok(f"No results for plugin {plugin_name}")

        # add the results to the statistic and print/log them
        with self._term.indent():
            for plugin_result in plugin_results:
                if isinstance(plugin_result, LinterError):
                    self._result_counts.add_error(plugin_name)
                    report = self._report_error
                elif isinstance(plugin_result, LinterWarning):
                    self._result_counts.add_warning(plugin_name)
                    report = self._report_warning
                elif isinstance(plugin_result, LinterFix):
                    self._result_counts.add_fix(plugin_name)
                    report = self._report_ok
                elif isinstance(plugin_result, LinterResult):
                    report = self._report_ok

                if self._verbose > 0:
                    report(plugin_result.message)

    def report_single_run_plugin(
        self, plugin_name: str, plugin_results: List
    ) -> None:
        """Print/log the report of a single run plugin

        Arguments:
            plugin_name     name of the plugin
            plugin_results  a List of results for the plugin
        """
        with self._term.indent():
            if plugin_results and self._verbose > 0 or self._verbose > 1:
                self._report_bold_info(f"Run plugin {plugin_name}")

            self._process_plugin_results(
                plugin_name=plugin_name, plugin_results=plugin_results
            )

    def report_by_file_plugin(
        self, file_results: FileResults, pos: int
    ) -> None:
        """Print/log the results of all plugins for a specific file

        Arguments:
            file_results    a file results object
            pos             the absolute file number in relation
                            to the whole file count
        """
        if file_results and self._verbose > 0 or self._verbose > 1:
            # only print the part "common/some_nasl.nasl"
            from_root_path = get_path_from_root(
                file_results.file_path, self._root
            )
            self._report_bold_info(
                f"Checking {from_root_path} ({pos}/{self._files_count})"
            )

        with self._term.indent():

            # print the files plugin results
            for (
                plugin_name,
                plugin_results,
            ) in file_results.plugin_results.items():
                self._process_plugin_results(plugin_name, plugin_results)

    def report_plugin_overview(
        self,
        plugins: Plugins,
        excluded: Iterable[str],
        included: Iterable[str],
        pre_run: Iterable[FilesPlugin],
    ) -> None:
        """Print/log an overview, which plugins are in-/excluded and which one
        will be executed"""
        if self._verbose > 2:
            if pre_run:
                self.report_info(
                    "Pre-Run Plugins: "
                    f"{', '.join([p.name for p in pre_run])}"
                )

            if excluded:
                self.report_info(f"Excluded Plugins: {', '.join(excluded)}")

            if included:
                self.report_info(f"Included Plugins: {', '.join(included)}")

            self.report_info(
                f"Running plugins: {', '.join([p.name for p in plugins])}"
            )

    def report_statistic(self) -> None:
        """Print a Error/Warning summary from the different plugins"""
        if not self._statistic:
            return

        if self._fix:
            self._term.print(
                f"{'Plugin':48} {'  Errors':8} {'Warnings':8} {'   Fixes':8}"
            )
        else:
            self._term.print(f"{'Plugin':48} {'  Errors':8} {'Warnings':8}")

        length = 75 if self._fix else 67
        self._term.print("-" * length)

        for (plugin, count) in self._result_counts.result_counts.items():
            if self._fix:
                line = (
                    f"{plugin:48} {count['error']:8} {count['warning']:8}"
                    f" {count['fix']:8}"
                )
            else:
                line = f"{plugin:48} {count['error']:8} {count['warning']:8}"

            if count["error"] > 0:
                self._term.error(line)
            else:
                self._term.warning(line)

        self._term.print("-" * length)

        if self._fix:
            self._term.info(
                f"{'sum':48} {self._result_counts.error_count:8}"
                f" {self._result_counts.warning_count:8}"
                f" {self._result_counts.fix_count:8}"
            )
        else:
            self._term.info(
                f"{'sum':48} {self._result_counts.error_count:8}"
                f" {self._result_counts.warning_count:8}"
            )

    def _log_append(self, message: str):
        if self._log_file:
            with self._log_file.open(mode="a", encoding="utf-8") as f:
                f.write(f"{message}\n")

    def plugin_not_found(self, plugin_name):
        self._report_error(f"Plugin {plugin_name} is not existing.")

    def plugin_unknown(self, plugin_name):
        self._report_error(f"Plugin {plugin_name} can not be read.")

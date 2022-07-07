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

from pontos.terminal import Terminal

from troubadix.helper.helper import get_path_from_root
from troubadix.plugin import LinterError, LinterFix, LinterResult, LinterWarning
from troubadix.plugins import Plugins
from troubadix.results import FileResults, ResultCounts, Results


class Reporter:
    def __init__(
        self,
        term: Terminal,
        root: Path,
        *,
        fix: bool = False,
        log_file: Path = None,
        log_file_statistic: Path = None,
        statistic: bool = True,
        verbose: int = 0,
        ignore_warnings: bool = False,
    ) -> None:
        self._term = term
        self._log_file = log_file
        self._log_file_statistic = log_file_statistic
        self._statistic = statistic
        self._verbose = verbose
        self._fix = fix
        self._files_count = 0
        self._root = root
        self._ignore_warnings = ignore_warnings
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

    def report_by_plugin(self, results: Results) -> None:
        """Print/log results per plugins

        Arguments:
            results    a results object
        """
        for (
            plugin_name,
            plugin_results,
        ) in results.plugin_results.items():
            if results and self._verbose > 0 or self._verbose > 1:
                self._report_bold_info(f"Run plugin {plugin_name}")

            with self._term.indent():
                self._process_plugin_results(plugin_name, plugin_results)

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
    ) -> None:
        """Print/log an overview, which plugins are in-/excluded and which one
        will be executed"""
        if self._verbose > 2:
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

        if self._fix and self._ignore_warnings:
            line = f"{'Plugin':48} {'  Errors':8} {'   Fixes':8}"
            length = "-" * 67
        elif self._fix:
            line = f"{'Plugin':48} {'  Errors':8} {'Warnings':8} {'   Fixes':8}"
            length = "-" * 75
        elif self._ignore_warnings:
            line = f"{'Plugin':48} {'  Errors':8}"
            length = "-" * 59
        else:
            line = f"{'Plugin':48} {'  Errors':8} {'Warnings':8}"
            length = "-" * 67

        self._term.print(line)
        self._log_statistic_append(line)
        self._term.print(length)
        self._log_statistic_append(length)

        for (plugin, count) in self._result_counts.result_counts.items():
            if self._fix and self._ignore_warnings:
                line = f"{plugin:48} {count['error']:8} {count['fix']:8}"
            elif self._fix:
                line = (
                    f"{plugin:48} {count['error']:8} {count['warning']:8}"
                    f" {count['fix']:8}"
                )
            elif self._ignore_warnings:
                line = f"{plugin:48} {count['error']:8}"
            else:
                line = f"{plugin:48} {count['error']:8} {count['warning']:8}"

            if count["error"] > 0:
                self._term.error(line)
                self._log_statistic_append(line)
            else:
                self._term.warning(line)
                self._log_statistic_append(line)

        self._term.print(length)
        self._log_statistic_append(length)

        if self._fix and self._ignore_warnings:
            line = (
                f"{'sum':48} {self._result_counts.error_count:8}"
                f" {self._result_counts.fix_count:8}"
            )
        elif self._fix:
            line = (
                f"{'sum':48} {self._result_counts.error_count:8}"
                f" {self._result_counts.warning_count:8}"
                f" {self._result_counts.fix_count:8}"
            )
        elif self._ignore_warnings:
            line = f"{'sum':48} {self._result_counts.error_count:8}"
        else:
            line = (
                f"{'sum':48} {self._result_counts.error_count:8}"
                f" {self._result_counts.warning_count:8}"
            )

        self._term.info(line)
        self._log_statistic_append(line)

    def _log_append(self, message: str):
        if self._log_file:
            with self._log_file.open(mode="a", encoding="utf-8") as f:
                f.write(f"{message}\n")

    def _log_statistic_append(self, message: str):
        if self._log_file_statistic:
            with self._log_file_statistic.open(mode="a", encoding="utf-8") as f:
                f.write(f"{message}\n")

    def plugin_not_found(self, plugin_name):
        self._report_error(f"Plugin {plugin_name} is not existing.")

    def plugin_unknown(self, plugin_name):
        self._report_error(f"Plugin {plugin_name} can not be read.")

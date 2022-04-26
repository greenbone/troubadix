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
from typing import Iterable
from pontos.terminal.terminal import Terminal

from troubadix.plugin import (
    LinterError,
    LinterFix,
    LinterMessage,
    LinterResult,
    LinterWarning,
)


class Reporter:
    def __init__(
        self,
        term: Terminal,
        *,
        log_file: Path = None,
        statistic: bool = True,
        verbose: int = 0,
    ) -> None:
        self._term = term
        self._log_file = log_file
        self._statistic = statistic
        self._verbose = verbose

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

    def _report_results(self, results: Iterable[LinterMessage]) -> None:
        for result in results:
            if isinstance(result, (LinterResult, LinterFix)):
                self._report_ok(result.message)
            elif isinstance(result, LinterError):
                self._report_error(result.message)
            elif isinstance(result, LinterWarning):
                self._report_warning(result.message)

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
        """Print a Error/Warning summary from the different plugins"""
        if self._fix:
            self._term.print(
                f"{'Plugin':50} {'  Errors':8}  {'Warnings':8}  {'   Fixes':8}"
            )
        else:
            self._term.print(f"{'Plugin':50} {'  Errors':8}  {'Warnings':8}")

        length = 79 if self._fix else 69
        self._term.print("-" * length)

        for (plugin, count) in self.result_counts.result_counts.items():
            if self._fix:
                line = (
                    f"{plugin:50} {count['error']:8}  {count['warning']:8}  "
                    f"{count['fix']:8}"
                )
            else:
                line = f"{plugin:50} {count['error']:8}  {count['warning']:8}  "

            if count["error"] > 0:
                self._term.error(line)
            else:
                self._term.warning(line)

        self._term.print("-" * length)

        if self._fix:
            self._term.info(
                f"{'sum':50} {self.result_counts.warning_count:8}"
                f"  {self.result_counts.error_count:8}"
                f"  {self.result_counts.fix_count:8}"
            )
        else:
            self._term.info(
                f"{'sum':50} {self.result_counts.warning_count:8}"
                f"  {self.result_counts.error_count:8}"
            )

    def _log_append(self, message: str):
        if self._log_file:
            with self._log_file.open(mode="a", encoding="utf-8") as f:
                f.write(f"{message}\n")

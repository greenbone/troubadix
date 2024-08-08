# Copyright (C) 2022 Greenbone AG
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

from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path

from troubadix.plugin import LinterResult, LinterWarning


class Results:
    def __init__(self, ignore_warnings: bool = False) -> None:
        self.plugin_results: dict[str, list[LinterResult]] = defaultdict(list)
        self.has_plugin_results = False
        self._ignore_warnings = ignore_warnings

    def add_plugin_results(
        self, plugin_name: str, results: Iterator[LinterResult]
    ) -> "Results":
        if self._ignore_warnings:
            results = [
                result
                for result in results
                if not isinstance(result, LinterWarning)
            ]
        else:
            results = list(results)

        self.has_plugin_results = self.has_plugin_results or bool(results)
        self.plugin_results[plugin_name] += results
        return self

    def __bool__(self):
        return self.has_plugin_results


class FileResults(Results):
    """Class to store results from different plugins for a file"""

    def __init__(self, file_path: Path, ignore_warnings: bool = False):
        self.file_path = file_path
        super().__init__(ignore_warnings)


def resultsdict():
    return defaultdict(int)


class ResultCounts:
    """Class that counts different types of results of different plugins"""

    def __init__(self):
        self.result_counts = defaultdict(resultsdict)
        self.error_count = 0
        self.warning_count = 0
        self.fix_count = 0

    def add_error(self, plugin: str):
        self.error_count += 1
        self.result_counts[plugin]["error"] += 1

    def add_warning(self, plugin: str):
        self.warning_count += 1
        self.result_counts[plugin]["warning"] += 1

    def add_fix(self, plugin: str):
        self.fix_count += 1
        self.result_counts[plugin]["fix"] += 1

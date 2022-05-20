# Copyright (C) 2021-2022 Greenbone Networks GmbH
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
from multiprocessing import Pool
from pathlib import Path
from typing import Iterable

from troubadix.helper.patterns import (
    init_script_tag_patterns,
    init_special_script_tag_patterns,
)
from troubadix.plugin import FilePluginContext, FilesPlugin, FilesPluginContext
from troubadix.plugins import Plugins, StandardPlugins, UpdatePlugins
from troubadix.reporter import Reporter
from troubadix.results import FileResults

CHUNKSIZE = 1  # default 1


class TroubadixException(Exception):
    """Generic Exception for Troubadix"""


def initializer():
    """Ignore CTRL+C in the worker process."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)


class Runner:
    def __init__(
        self,
        n_jobs: int,
        reporter: Reporter,
        *,
        root: Path,
        excluded_plugins: Iterable[str] = None,
        included_plugins: Iterable[str] = None,
        update_date: bool = False,
        fix: bool = False,
    ) -> bool:
        # plugins initialization
        self.plugins: Plugins = (
            UpdatePlugins()
            if update_date
            else StandardPlugins(excluded_plugins, included_plugins)
        )
        self._excluded_plugins = excluded_plugins
        self._included_plugins = included_plugins
        self.pre_run_plugins = self.plugins.get_prerun_plugins()

        self._reporter = reporter
        self._n_jobs = n_jobs
        self._root = root
        self._fix = fix or update_date

        init_script_tag_patterns()
        init_special_script_tag_patterns()

    def _check_files(self, nasl_files: Iterable[Path]) -> None:
        """Running Plugins that do not require a run per file,
        but a single execution"""
        context = FilesPluginContext(root=self._root, nasl_files=nasl_files)
        for plugin_class in self.pre_run_plugins:
            if not issubclass(plugin_class, FilesPlugin):
                self._reporter.plugin_unknown(plugin_name=plugin_class.name)
                continue

            plugin = plugin_class(context)

            results = list(plugin.run())

            if self._fix:
                results.extend(plugin.fix())

            self._reporter.report_single_run_plugin(
                plugin_name=plugin.name, plugin_results=results
            )

    def _check_file(self, file_path: Path) -> FileResults:
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

            if self._fix:
                results.add_plugin_results(plugin.name, plugin.fix())

        return results

    def _check_single_files(self, files: Iterable[Path]):
        """Run all plugins that check single files"""
        self._reporter.set_files_count(len(files))
        with Pool(processes=self._n_jobs, initializer=initializer) as pool:
            try:
                for i, results in enumerate(
                    iterable=pool.imap_unordered(
                        self._check_file, files, chunksize=CHUNKSIZE
                    ),
                    start=1,
                ):
                    self._reporter.report_by_file_plugin(
                        file_results=results, pos=i
                    )

            except KeyboardInterrupt:
                pool.terminate()
                pool.join()

    def run(self, files: Iterable[Path]) -> bool:
        """The function that should be executed to run
        the Plugins over all files"""
        if not len(self.plugins) and not len(self.pre_run_plugins):
            raise TroubadixException("No Plugin found.")

        # print plugins that will be executed
        self._reporter.report_plugin_overview(
            plugins=self.plugins,
            excluded=self._excluded_plugins,
            included=self._included_plugins,
            pre_run=self.pre_run_plugins,
        )

        start = datetime.datetime.now()
        if len(self.pre_run_plugins):
            self._check_files(files)
        if len(self.plugins):
            self._check_single_files(files)

        self._reporter.report_info(
            f"Time elapsed: {datetime.datetime.now() - start}"
        )
        self._reporter.report_statistic()

        # Return true if no error exists
        return self._reporter.get_error_count() == 0

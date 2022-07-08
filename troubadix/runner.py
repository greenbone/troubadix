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
from troubadix.plugin import FilePluginContext, FilesPluginContext, Plugin
from troubadix.plugins import StandardPlugins
from troubadix.reporter import Reporter
from troubadix.results import FileResults, Results

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
        fix: bool = False,
        ignore_warnings: bool = False,
    ) -> bool:
        # plugins initialization
        self.plugins = StandardPlugins(excluded_plugins, included_plugins)

        self._excluded_plugins = excluded_plugins
        self._included_plugins = included_plugins

        self._reporter = reporter
        self._n_jobs = n_jobs
        self._root = root
        self._fix = fix
        self._ignore_warnings = ignore_warnings

        init_script_tag_patterns()
        init_special_script_tag_patterns()

    def _check(self, plugin: Plugin, results: Results) -> Results:
        """Run a single plugin and collect the results"""
        results.add_plugin_results(plugin.name, plugin.run())

        if self._fix:
            results.add_plugin_results(plugin.name, plugin.fix())

        return results

    def _check_files(self, plugin: Plugin) -> Results:
        """Run a files plugin and collect the results"""
        results = Results(ignore_warnings=self._ignore_warnings)
        return self._check(plugin, results)

    def _check_file(self, file_path: Path) -> FileResults:
        """Run all file plugins on a single file and collect the results"""
        results = FileResults(file_path, ignore_warnings=self._ignore_warnings)
        context = FilePluginContext(
            root=self._root, nasl_file=file_path.resolve()
        )

        for plugin_class in self.plugins.file_plugins:
            plugin = plugin_class(context)

            self._check(plugin, results)

        return results

    def _run_pooled(self, files: Iterable[Path]):
        """Run all plugins that check single files"""
        self._reporter.set_files_count(len(files))
        with Pool(processes=self._n_jobs, initializer=initializer) as pool:
            try:
                # run files plugins
                context = FilesPluginContext(root=self._root, nasl_files=files)
                files_plugins = [
                    plugin_class(context)
                    for plugin_class in self.plugins.files_plugins
                ]

                for results in pool.imap_unordered(
                    self._check_files, files_plugins, chunksize=CHUNKSIZE
                ):
                    self._reporter.report_by_plugin(results)

                # run file plugins
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
        if not len(self.plugins):
            raise TroubadixException("No Plugin found.")

        # print plugins that will be executed
        self._reporter.report_plugin_overview(
            plugins=self.plugins,
            excluded=self._excluded_plugins,
            included=self._included_plugins,
        )

        start = datetime.datetime.now()
        self._run_pooled(files)

        self._reporter.report_info(
            f"Time elapsed: {datetime.datetime.now() - start}"
        )
        self._reporter.report_statistic()

        # Return true if no error exists
        return self._reporter.get_error_count() == 0

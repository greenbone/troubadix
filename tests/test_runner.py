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

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from pontos.terminal import _set_terminal
from pontos.terminal.terminal import Terminal

from troubadix.plugin import LinterError, LinterResult
from troubadix.plugins import _PLUGINS
from troubadix.runner import Runner, TroubadixException

_here = Path(__file__).parent


class TestRunner(unittest.TestCase):
    def setUp(self):
        # store old arguments
        self._term = Terminal()
        _set_terminal(self._term)

    def test_runner_with_all_plugins(self):
        runner = Runner(n_jobs=1, term=self._term)

        plugins = _PLUGINS

        for plugin in runner.plugins.plugins:
            self.assertIn(plugin, plugins)

    def test_runner_with_excluded_plugins(self):
        excluded_plugins = [
            "CheckBadwords",
            "CheckCopyRightYearPlugin",
        ]
        included_plugins = [
            plugin.__name__
            for plugin in _PLUGINS
            if plugin.__name__ not in excluded_plugins
        ]
        runner = Runner(
            n_jobs=1,
            term=self._term,
            excluded_plugins=excluded_plugins,
        )

        for plugin in runner.plugins.plugins:
            self.assertIn(plugin.__name__, included_plugins)

    def test_runner_with_included_plugins(self):
        included_plugins = [
            "CheckBadwords",
            "CheckCopyRightYearPlugin",
        ]
        runner = Runner(
            n_jobs=1,
            term=self._term,
            included_plugins=included_plugins,
        )

        for plugin in runner.plugins.plugins:
            self.assertIn(plugin.__name__, included_plugins)

    def test_runner_run_ok(self):
        nasl_file = _here / "plugins" / "test.nasl"
        content = nasl_file.read_text(encoding="latin1")

        runner = Runner(
            n_jobs=1,
            term=self._term,
            update_date=True,
        )

        results = runner.check_file(nasl_file)

        new_content = nasl_file.read_text(encoding="latin1")
        self.assertNotEqual(content, new_content)

        self.assertEqual(len(results.generic_results), 0)
        self.assertEqual(len(results.plugin_results), 1)
        self.assertEqual(
            len(results.plugin_results["update_modification_date"]), 1
        )
        self.assertIsInstance(
            results.plugin_results["update_modification_date"][0],
            LinterResult,
        )

        # revert changes for the next time
        nasl_file.write_text(content, encoding="latin1")

    def test_runner_run_error(self):
        nasl_file = _here / "plugins" / "fail.nasl"
        content = nasl_file.read_text(encoding="latin1")

        runner = Runner(
            n_jobs=1,
            term=self._term,
            update_date=True,
        )

        results = runner.check_file(nasl_file)

        new_content = nasl_file.read_text(encoding="latin1")
        self.assertEqual(content, new_content)

        self.assertEqual(len(results.generic_results), 0)
        self.assertEqual(len(results.plugin_results), 1)
        self.assertEqual(
            len(results.plugin_results["update_modification_date"]), 1
        )

        error = results.plugin_results["update_modification_date"][0]
        self.assertIsInstance(error, LinterError)
        self.assertIn(
            "fail.nasl does not contain a modification day script tag.",
            error.message,
        )

    def test_runner_run_fail_with_verbose_level_2(self):
        nasl_file = _here / "plugins" / "fail.nasl"
        content = nasl_file.read_text(encoding="latin1")

        runner = Runner(
            n_jobs=1,
            term=self._term,
            update_date=True,
            verbose=2,
        )

        with redirect_stdout(io.StringIO()) as f:
            runner.run([nasl_file])

            new_content = nasl_file.read_text(encoding="latin1")
            self.assertEqual(content, new_content)

        output = f.getvalue()
        self.assertIn(f"Checking {nasl_file}", output)
        self.assertIn("Results for plugin update_modification_date", output)
        # CI terminal formats for 80 chars per line
        self.assertIn(
            "fail.nasl does not",
            output,
        )
        self.assertIn(
            "contain a modification day script tag.",
            output,
        )

    def test_runner_run_changed_with_verbose_level_1(self):
        nasl_file = _here / "plugins" / "test.nasl"
        content = nasl_file.read_text(encoding="latin1")

        runner = Runner(
            verbose=1,
            n_jobs=1,
            term=self._term,
            update_date=True,
        )

        with redirect_stdout(io.StringIO()) as f:
            runner.run([nasl_file])

            new_content = nasl_file.read_text(encoding="latin1")
            self.assertNotEqual(content, new_content)

        output = f.getvalue()
        self.assertIn(f"Checking {nasl_file}", output)
        self.assertIn("Results for plugin update_modification_date", output)
        self.assertIn(
            "Replaced modification_date 2021-03-24 10:08:26 +0000"
            " (Wed, 24 Mar 2021",
            output,
        )

        # revert changes for the next time
        nasl_file.write_text(content, encoding="latin1")

    def test_runner_run_ok_with_verbose_level_2(self):
        included_plugins = [
            "CheckMissingDescExit",
        ]
        nasl_file = _here / "plugins" / "test.nasl"
        content = nasl_file.read_text(encoding="latin1")

        runner = Runner(
            n_jobs=1,
            term=self._term,
            included_plugins=included_plugins,
            verbose=2,
        )

        with redirect_stdout(io.StringIO()) as f:
            runner.run([nasl_file])

            new_content = nasl_file.read_text(encoding="latin1")
            self.assertEqual(content, new_content)

        output = f.getvalue()
        self.assertIn(f"Checking {nasl_file}", output)
        self.assertIn("No results for plugin", output)

    def test_runner_run_ok_with_verbose_level_1(self):
        included_plugins = [
            "CheckMissingDescExit",
        ]
        nasl_file = _here / "plugins" / "test.nasl"
        content = nasl_file.read_text(encoding="latin1")

        runner = Runner(
            verbose=1,
            n_jobs=1,
            term=self._term,
            included_plugins=included_plugins,
        )

        with redirect_stdout(io.StringIO()) as f:
            runner.run([nasl_file])

            new_content = nasl_file.read_text(encoding="latin1")
            self.assertEqual(content, new_content)

        output = f.getvalue()
        self.assertIn(f"Checking {nasl_file}", output)
        self.assertNotIn("Results for plugin check_missing_desc_exit", output)

        # revert changes for the next time
        nasl_file.write_text(content, encoding="latin1")

    def test_no_plugins(self):
        runner = Runner(
            n_jobs=1,
            term=self._term,
            included_plugins=["foo"],
        )

        nasl_file = _here / "plugins" / "test.nasl"

        with self.assertRaises(TroubadixException):
            runner.run([nasl_file])

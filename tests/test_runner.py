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
from troubadix.helper import CURRENT_ENCODING
from troubadix.helper.helper import get_path_from_root

from troubadix.plugin import LinterError, LinterResult
from troubadix.plugins import _PLUGINS
from troubadix.runner import Runner, TroubadixException

_here = Path(__file__).parent


class TestRunner(unittest.TestCase):
    def setUp(self):
        # store old arguments
        self._term = Terminal()
        self.root = _here / "plugins" / "test_files" / "nasl"
        _set_terminal(self._term)

    def test_runner_with_all_plugins(self):
        runner = Runner(
            n_jobs=1,
            term=self._term,
            root=self.root,
        )

        plugins = _PLUGINS

        for plugin in runner.plugins:
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
            root=self.root,
        )

        for plugin in runner.plugins:
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
            root=self.root,
        )

        for plugin in runner.plugins:
            self.assertIn(plugin.__name__, included_plugins)

    def test_runner_run_ok(self):
        nasl_file = (
            _here
            / "plugins"
            / "test_files"
            / "nasl"
            / "21.04"
            / "runner"
            / "test_valid_oid.nasl"
        )
        content = nasl_file.read_text(encoding=CURRENT_ENCODING)

        # Check sys exit 1
        included_plugins = [
            "CheckMissingDescExit",
        ]
        runner = Runner(
            n_jobs=1,
            included_plugins=included_plugins,
            term=self._term,
            root=self.root,
        )
        with redirect_stdout(io.StringIO()) as _:
            sys_exit = runner.run([nasl_file])

        self.assertFalse(sys_exit)

        # Test update_date
        runner = Runner(
            n_jobs=1,
            term=self._term,
            update_date=True,
            root=self.root,
        )

        results = runner.check_file(nasl_file)

        new_content = nasl_file.read_text(encoding=CURRENT_ENCODING)
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
        nasl_file.write_text(content, encoding=CURRENT_ENCODING)

    def test_runner_run_error(self):
        nasl_file = (
            _here
            / "plugins"
            / "test_files"
            / "nasl"
            / "21.04"
            / "runner"
            / "fail.nasl"
        )
        content = nasl_file.read_text(encoding=CURRENT_ENCODING)

        # Check sys exit 1
        included_plugins = [
            "CheckCVSSFormat",
        ]
        runner = Runner(
            n_jobs=1,
            included_plugins=included_plugins,
            term=self._term,
            root=self.root,
        )

        with redirect_stdout(io.StringIO()) as _:
            sys_exit = runner.run([nasl_file])

        self.assertTrue(sys_exit)

        # Test update_date
        runner = Runner(
            n_jobs=1,
            term=self._term,
            update_date=True,
            root=self.root,
        )

        results = runner.check_file(nasl_file)

        new_content = nasl_file.read_text(encoding=CURRENT_ENCODING)
        self.assertEqual(content, new_content)

        self.assertEqual(len(results.generic_results), 0)
        self.assertEqual(len(results.plugin_results), 1)
        self.assertEqual(
            len(results.plugin_results["update_modification_date"]), 1
        )

        error = results.plugin_results["update_modification_date"][0]
        self.assertIsInstance(error, LinterError)
        self.assertIn(
            "VT does not contain a modification day script tag.",
            error.message,
        )

    def test_runner_run_fail_with_verbose_level_2(self):
        nasl_file = (
            _here
            / "plugins"
            / "test_files"
            / "nasl"
            / "21.04"
            / "runner"
            / "fail.nasl"
        )
        content = nasl_file.read_text(encoding=CURRENT_ENCODING)

        runner = Runner(
            n_jobs=1,
            term=self._term,
            update_date=True,
            verbose=2,
            root=self.root,
        )

        with redirect_stdout(io.StringIO()) as f:
            runner.run([nasl_file])

            new_content = nasl_file.read_text(encoding=CURRENT_ENCODING)
            self.assertEqual(content, new_content)

        output = f.getvalue()
        self.assertIn(
            f"Checking {get_path_from_root(nasl_file, self.root)}",
            output,
        )
        self.assertIn("Results for plugin update_modification_date", output)
        # CI terminal formats for 80 chars per line
        self.assertIn(
            "VT does not contain a modification day script tag.",
            output,
        )

    def test_runner_run_changed_with_verbose_level_1(self):
        nasl_file = (
            _here
            / "plugins"
            / "test_files"
            / "nasl"
            / "21.04"
            / "runner"
            / "test.nasl"
        )
        content = nasl_file.read_text(encoding=CURRENT_ENCODING)

        runner = Runner(
            verbose=1,
            n_jobs=1,
            term=self._term,
            update_date=True,
            root=self.root,
        )

        with redirect_stdout(io.StringIO()) as f:
            runner.run([nasl_file])

            new_content = nasl_file.read_text(encoding=CURRENT_ENCODING)
            self.assertNotEqual(content, new_content)

        output = f.getvalue()
        self.assertIn(
            "Checking " f"{get_path_from_root(nasl_file, self.root)}",
            output,
        )
        self.assertIn("Results for plugin update_modification_date", output)
        self.assertIn(
            "Replaced modification_date 2021-03-24 10:08:26 +0000"
            " (Wed, 24 Mar 2021",
            output,
        )

        # revert changes for the next time
        nasl_file.write_text(content, encoding=CURRENT_ENCODING)

    def test_runner_run_ok_with_verbose_level_3(self):
        included_plugins = [
            "CheckMissingDescExit",
        ]
        nasl_file = (
            _here
            / "plugins"
            / "test_files"
            / "nasl"
            / "21.04"
            / "runner"
            / "test.nasl"
        )
        content = nasl_file.read_text(encoding=CURRENT_ENCODING)

        runner = Runner(
            n_jobs=1,
            term=self._term,
            included_plugins=included_plugins,
            verbose=3,
            root=self.root,
        )

        with redirect_stdout(io.StringIO()) as f:
            runner.run([nasl_file])

            new_content = nasl_file.read_text(encoding=CURRENT_ENCODING)
            self.assertEqual(content, new_content)

        output = f.getvalue()
        self.assertIn(
            f"Checking {get_path_from_root(nasl_file, self.root)}", output
        )
        self.assertIn("No results for plugin check_missing_desc_exit", output)

    def test_runner_run_ok_with_verbose_level_2(self):
        included_plugins = [
            "CheckMissingDescExit",
        ]
        nasl_file = (
            _here
            / "plugins"
            / "test_files"
            / "nasl"
            / "21.04"
            / "runner"
            / "test.nasl"
        )
        content = nasl_file.read_text(encoding=CURRENT_ENCODING)

        runner = Runner(
            n_jobs=1,
            term=self._term,
            included_plugins=included_plugins,
            verbose=2,
            root=self.root,
        )

        with redirect_stdout(io.StringIO()) as f:
            runner.run([nasl_file])

            new_content = nasl_file.read_text(encoding=CURRENT_ENCODING)
            self.assertEqual(content, new_content)

        output = f.getvalue()
        self.assertIn(
            "Checking " f"{get_path_from_root(nasl_file, self.root)}",
            output,
        )
        self.assertNotIn(
            "No results for plugin check_missing_desc_exit", output
        )

    def test_runner_run_ok_with_verbose_level_1(self):
        included_plugins = [
            "CheckMissingDescExit",
        ]
        nasl_file = (
            _here
            / "plugins"
            / "test_files"
            / "nasl"
            / "21.04"
            / "runner"
            / "test.nasl"
        )
        content = nasl_file.read_text(encoding=CURRENT_ENCODING)

        runner = Runner(
            verbose=1,
            n_jobs=1,
            term=self._term,
            included_plugins=included_plugins,
            root=self.root,
        )

        with redirect_stdout(io.StringIO()) as f:
            runner.run([nasl_file])

            new_content = nasl_file.read_text(encoding=CURRENT_ENCODING)
            self.assertEqual(content, new_content)

        output = f.getvalue()
        self.assertNotIn(
            "No results for plugin check_missing_desc_exit", output
        )
        self.assertNotIn("Results for plugin check_missing_desc_exit", output)

        # revert changes for the next time
        nasl_file.write_text(content, encoding=CURRENT_ENCODING)

    def test_no_plugins(self):
        runner = Runner(
            n_jobs=1,
            term=self._term,
            included_plugins=["foo"],
            root=self.root,
        )

        nasl_file = _here / "plugins" / "test.nasl"

        with self.assertRaises(TroubadixException):
            runner.run([nasl_file])

    def test_runner_log_file(self):
        included_plugins = [
            "CheckMissingDescExit",
        ]
        nasl_file = (
            _here
            / "plugins"
            / "test_files"
            / "nasl"
            / "21.04"
            / "runner"
            / "test.nasl"
        )
        gen_log_file = _here / "gen_log.txt"

        runner = Runner(
            verbose=3,
            n_jobs=1,
            term=self._term,
            included_plugins=included_plugins,
            log_file=gen_log_file,
            root=self.root,
        )
        with redirect_stdout(io.StringIO()):
            runner.run([nasl_file])

        compare_content = (
            "\tPre-Run Plugins: check_duplicate_oid, check_no_solution\n"
            "\tIncluded Plugins: CheckMissingDescExit\n\t"
            "Running plugins: check_missing_desc_exit\n\n\n"
            "Run plugin check_duplicate_oid\n"
            "\tResults for plugin check_duplicate_oid\n"
            f"\t\t{get_path_from_root(nasl_file, self.root)}: Invalid OID "
            "1.2.3.4.5.6.78909.1.7.654321 found.\n\n\n"
            "Run plugin check_no_solution\n"
            "\t\tNo results for plugin check_no_solution\n\n\n"
            f"Checking {get_path_from_root(nasl_file, self.root)} (0/1)\n\t\t"
            "No results for plugin"
            " check_missing_desc_exit\n\tTime elapsed: 0:00:00.013967"
        )
        gen_content = gen_log_file.read_text(encoding="utf-8")
        gen_log_file.unlink()
        # Remove Time elapsed line
        self.assertEqual(
            compare_content.splitlines()[:-1],
            gen_content.splitlines()[:-1],
        )

    def test_runner_log_file_fail(self):
        included_plugins = [
            "CheckMissingDescExit",
        ]
        nasl_file = (
            _here
            / "plugins"
            / "test_files"
            / "nasl"
            / "21.04"
            / "runner"
            / "test.nasl"
        )
        gen_log_file = _here / "gen_log.txt"

        runner = Runner(
            verbose=2,
            n_jobs=1,
            term=self._term,
            included_plugins=included_plugins,
            log_file=gen_log_file,
            root=self.root,
        )
        with redirect_stdout(io.StringIO()):
            runner.run([nasl_file])

        compare_content = (
            "\tIncluded Plugins: CheckMissingDescExit\n\t"
            "Running plugins: check_missing_desc_exit\n\n\nChecking"
            "Run plugin check_duplicate_oid"
            f"\t\t{get_path_from_root(nasl_file, self.root)}: "
            "Invalid OID 1.2.3.4.5.6.78909.1.7.654321 found."
            f" {get_path_from_root(nasl_file, self.root)} (0/1)\n"
            "\tNo results for plugin"
            " check_missing_desc_exit\n\tTime elapsed: 0:00:00.013967"
        )
        gen_content = gen_log_file.read_text(encoding="utf-8")
        gen_log_file.unlink()
        # Remove Time elapsed line
        self.assertNotEqual(
            compare_content.splitlines()[:-1],
            gen_content.splitlines()[:-1],
        )

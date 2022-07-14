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
# pylint: disable=protected-access

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from pontos.terminal.terminal import ConsoleTerminal

from troubadix.helper import CURRENT_ENCODING
from troubadix.helper.helper import get_path_from_root
from troubadix.plugins import _FILE_PLUGINS, _FILES_PLUGINS
from troubadix.plugins.badwords import CheckBadwords
from troubadix.plugins.copyright_text import CheckCopyrightText
from troubadix.plugins.cvss_format import CheckCVSSFormat
from troubadix.plugins.duplicate_oid import CheckDuplicateOID
from troubadix.plugins.missing_desc_exit import CheckMissingDescExit
from troubadix.plugins.no_solution import CheckNoSolution
from troubadix.plugins.script_version_and_last_modification_tags import (
    CheckScriptVersionAndLastModificationTags,
)
from troubadix.reporter import Reporter
from troubadix.runner import Runner, TroubadixException

_here = Path(__file__).parent


class TestRunner(unittest.TestCase):
    def setUp(self):
        self._term = ConsoleTerminal()
        self.root = _here / "plugins" / "test_files" / "nasl"
        self._reporter = Reporter(term=self._term, root=self.root)

    def test_runner_with_all_plugins(self):
        runner = Runner(
            n_jobs=1,
            reporter=self._reporter,
            root=self.root,
        )

        plugins = _FILE_PLUGINS + _FILES_PLUGINS

        for plugin in runner.plugins:
            self.assertIn(plugin, plugins)

    def test_runner_with_excluded_plugins(self):
        excluded_plugins = [
            "CheckBadwords",
            "CheckCopyRightYearPlugin",
        ]
        included_plugins = [
            plugin.__name__
            for plugin in _FILE_PLUGINS + _FILES_PLUGINS
            if plugin.__name__ not in excluded_plugins
        ]
        runner = Runner(
            n_jobs=1,
            reporter=self._reporter,
            excluded_plugins=excluded_plugins,
            root=self.root,
        )

        for plugin in runner.plugins:
            self.assertIn(plugin.__name__, included_plugins)

    def test_runner_with_included_plugins(self):
        included_plugins = [
            CheckBadwords.name,
            CheckCopyrightText.name,
        ]
        runner = Runner(
            n_jobs=1,
            reporter=self._reporter,
            included_plugins=included_plugins,
            root=self.root,
        )

        self.assertEqual(len(runner.plugins), 2)

        for plugin in runner.plugins:
            self.assertIn(plugin.name, included_plugins)

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
        included_plugins = [
            CheckMissingDescExit.name,
        ]
        runner = Runner(
            n_jobs=1,
            reporter=self._reporter,
            included_plugins=included_plugins,
            root=self.root,
        )
        with redirect_stdout(io.StringIO()) as _:
            sys_exit = runner.run([nasl_file])

        self.assertTrue(sys_exit)
        self.assertEqual(self._reporter._result_counts.error_count, 0)
        self.assertEqual(self._reporter._result_counts.warning_count, 0)
        self.assertEqual(self._reporter._result_counts.fix_count, 0)
        self.assertEqual(
            self._reporter._result_counts.result_counts[
                CheckMissingDescExit.name
            ]["error"],
            0,
        )
        self.assertEqual(
            self._reporter._result_counts.result_counts[
                CheckMissingDescExit.name
            ]["warning"],
            0,
        )
        self.assertEqual(
            self._reporter._result_counts.result_counts[
                CheckMissingDescExit.name
            ]["fix"],
            0,
        )

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
        included_plugins = [CheckCVSSFormat.name, CheckNoSolution.name]
        runner = Runner(
            n_jobs=1,
            reporter=self._reporter,
            included_plugins=included_plugins,
            root=self.root,
        )

        with redirect_stdout(io.StringIO()) as _:
            sys_exit = runner.run([nasl_file])

        self.assertFalse(sys_exit)

        self.assertEqual(self._reporter._result_counts.error_count, 3)
        self.assertEqual(self._reporter._result_counts.warning_count, 0)
        self.assertEqual(self._reporter._result_counts.fix_count, 0)
        self.assertEqual(
            self._reporter._result_counts.result_counts[CheckCVSSFormat.name][
                "error"
            ],
            2,
        )
        self.assertEqual(
            self._reporter._result_counts.result_counts[CheckCVSSFormat.name][
                "warning"
            ],
            0,
        )
        self.assertEqual(
            self._reporter._result_counts.result_counts[CheckCVSSFormat.name][
                "fix"
            ],
            0,
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

        reporter = Reporter(term=self._term, root=self.root, verbose=2)

        runner = Runner(
            n_jobs=1,
            reporter=reporter,
            included_plugins=[CheckScriptVersionAndLastModificationTags.name],
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
        self.assertIn(
            "Results for plugin "
            "check_script_version_and_last_modification_tags",
            output,
        )
        # CI terminal formats for 80 chars per line
        self.assertIn(
            "VT is missing script_version();.",
            output,
        )

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

        reporter = Reporter(term=self._term, root=self.root, verbose=3)

        runner = Runner(
            n_jobs=1,
            reporter=reporter,
            included_plugins=included_plugins,
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

        reporter = Reporter(term=self._term, root=self.root, verbose=2)

        runner = Runner(
            n_jobs=1,
            reporter=reporter,
            included_plugins=included_plugins,
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

        reporter = Reporter(term=self._term, root=self.root, verbose=1)

        runner = Runner(
            reporter=reporter,
            n_jobs=1,
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
            reporter=self._reporter,
            included_plugins=["foo"],
            root=self.root,
        )

        nasl_file = _here / "plugins" / "test.nasl"

        with self.assertRaises(TroubadixException):
            runner.run([nasl_file])

    def test_runner_log_file(self):
        included_plugins = [
            CheckDuplicateOID.name,
            CheckMissingDescExit.name,
            CheckNoSolution.name,
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

        reporter = Reporter(
            term=self._term, root=self.root, verbose=3, log_file=gen_log_file
        )

        runner = Runner(
            reporter=reporter,
            n_jobs=1,
            included_plugins=included_plugins,
            root=self.root,
        )
        with redirect_stdout(io.StringIO()):
            runner.run([nasl_file])

        compare_content = (
            "\tIncluded Plugins: check_duplicate_oid, check_missing_desc_exit"
            ", check_no_solution\n"
            "\tRunning plugins: check_duplicate_oid, check_no_solution, "
            "check_missing_desc_exit\n"
            "\n\nRun plugin check_duplicate_oid\n"
            "\tResults for plugin check_duplicate_oid\n"
            "\t\tInvalid OID 1.2.3.4.5.6.78909.1.7.654321 found"
            " in '21.04/runner/test.nasl'.\n\n\n"
            "Run plugin check_no_solution\n"
            "\t\tNo results for plugin check_no_solution\n\n\n"
            f"Checking {get_path_from_root(nasl_file, self.root)} (1/1)\n\t\t"
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

        reporter = Reporter(
            term=self._term, root=self.root, log_file=gen_log_file
        )

        runner = Runner(
            n_jobs=1,
            reporter=reporter,
            included_plugins=included_plugins,
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

    def test_runner_run_ok_with_ignore_warnings(self):
        included_plugins = [
            "CheckCVEFormat",
        ]
        nasl_file = _here / "plugins" / "test_files" / "nasl" / "warning.nasl"
        content = nasl_file.read_text(encoding=CURRENT_ENCODING)

        reporter = Reporter(term=self._term, root=self.root)

        runner = Runner(
            n_jobs=1,
            reporter=reporter,
            included_plugins=included_plugins,
            root=self.root,
            ignore_warnings=True,
        )

        with redirect_stdout(io.StringIO()) as f:
            runner.run([nasl_file])

            new_content = nasl_file.read_text(encoding=CURRENT_ENCODING)
            self.assertEqual(content, new_content)

        output = f.getvalue()
        self.assertIn(f"{'sum':48} {0:8} {0:8}", output)

    def test_runner_run_fail_without_ignore_warnings(self):
        included_plugins = [
            "CheckCVEFormat",
        ]
        nasl_file = _here / "plugins" / "test_files" / "nasl" / "warning.nasl"
        content = nasl_file.read_text(encoding=CURRENT_ENCODING)

        reporter = Reporter(term=self._term, root=self.root)

        runner = Runner(
            n_jobs=1,
            reporter=reporter,
            included_plugins=included_plugins,
            root=self.root,
        )

        with redirect_stdout(io.StringIO()) as f:
            runner.run([nasl_file])

            new_content = nasl_file.read_text(encoding=CURRENT_ENCODING)
            self.assertEqual(content, new_content)

        output = f.getvalue()
        self.assertIn(f"{'sum':48} {0:8} {1:8}", output)

    def test_runner_log_file_statistic(self):
        included_plugins = [
            CheckDuplicateOID.name,
            CheckMissingDescExit.name,
            CheckNoSolution.name,
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

        reporter = Reporter(
            term=self._term,
            root=self.root,
            verbose=3,
            log_file_statistic=gen_log_file,
            ignore_warnings=True,
        )

        runner = Runner(
            reporter=reporter,
            n_jobs=1,
            included_plugins=included_plugins,
            root=self.root,
        )
        with redirect_stdout(io.StringIO()):
            runner.run([nasl_file])

        compare_content = (
            f"{'Plugin':50} Errors\n"
            f"{'-' * 59}\n"
            f"{'check_duplicate_oid':48} {1:8}\n"
            f"{'-' * 59}\n"
            f"{'sum':48} {1:8}\n"
        )
        gen_content = gen_log_file.read_text(encoding="utf-8")
        gen_log_file.unlink()

        self.assertEqual(compare_content, gen_content)

    def test_runner_fail_log_file_statistic(self):
        included_plugins = [
            CheckDuplicateOID.name,
            CheckMissingDescExit.name,
            CheckNoSolution.name,
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

        reporter = Reporter(
            term=self._term,
            root=self.root,
            verbose=3,
            log_file_statistic=gen_log_file,
            ignore_warnings=True,
            fix=True,
        )

        runner = Runner(
            reporter=reporter,
            n_jobs=1,
            included_plugins=included_plugins,
            root=self.root,
        )
        with redirect_stdout(io.StringIO()):
            runner.run([nasl_file])

        compare_content = (
            f"{'Plugin':50} Errors\n"
            f"{'-' * 59}\n"
            f"{'check_duplicate_oid':48} {1:8}\n"
            f"{'-' * 59}\n"
            f"{'sum':48} {1:8}\n"
        )
        gen_content = gen_log_file.read_text(encoding="utf-8")
        gen_log_file.unlink()

        self.assertNotEqual(compare_content, gen_content)

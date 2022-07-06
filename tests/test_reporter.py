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

from troubadix.reporter import Reporter

_here = Path(__file__).parent


class TestReporter(unittest.TestCase):
    def setUp(self):
        self._term = ConsoleTerminal()
        self.root = _here / "plugins" / "test_files" / "nasl"

    def test_set_files_count(self):
        reporter = Reporter(root=self.root, term=self._term)

        reporter.set_files_count(count=1)

        self.assertEqual(1, reporter._files_count)

    def test_get_error_count(self):
        reporter = Reporter(root=self.root, term=self._term)

        self.assertEqual(reporter.get_error_count(), 0)

    def test_report_statistic(self):
        reporter = Reporter(root=self.root, term=self._term)

        with redirect_stdout(io.StringIO()) as f:
            reporter.report_statistic()

        output = f.getvalue()

        self.assertIn("-" * 67, output)

        self.assertIn("Errors Warnings", output)
        self.assertIn(f"{'sum':48} {0:8} {0:8}", output)

    def test_report_statistic_with_fix_and_ignore_warnings(self):
        reporter = Reporter(
            root=self.root, term=self._term, fix=True, ignore_warnings=True
        )

        with redirect_stdout(io.StringIO()) as f:
            reporter.report_statistic()

        output = f.getvalue()

        self.assertIn("-" * 67, output)

        self.assertIn("Errors    Fixes", output)
        self.assertIn(f"{'sum':48} {0:8} {0:8}", output)

    def test_report_statistic_with_fix(self):
        reporter = Reporter(root=self.root, term=self._term, fix=True)

        with redirect_stdout(io.StringIO()) as f:
            reporter.report_statistic()

        output = f.getvalue()

        self.assertIn("-" * 75, output)

        self.assertIn("Errors Warnings    Fixes", output)
        self.assertIn(f"{'sum':48} {0:8} {0:8} {0:8}", output)

    def test_report_statistic_with_ignore_warnings(self):
        reporter = Reporter(
            root=self.root, term=self._term, ignore_warnings=True
        )

        with redirect_stdout(io.StringIO()) as f:
            reporter.report_statistic()

        output = f.getvalue()

        self.assertIn("-" * 59, output)

        self.assertIn("Errors", output)
        self.assertIn(f"{'sum':48} {0:8}", output)

    def test_report_statistic_none(self):
        reporter = Reporter(root=self.root, term=self._term, statistic=False)

        with redirect_stdout(io.StringIO()) as f:
            reporter.report_statistic()

        output = f.getvalue()

        self.assertFalse(output)

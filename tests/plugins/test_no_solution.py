# Copyright (c) 2022 Greenbone Networks GmbH
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

from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

from troubadix.helper import CURRENT_ENCODING
from troubadix.helper.helper import get_path_from_root
from troubadix.plugin import LinterWarning
from troubadix.plugins.no_solution import CheckNoSolution

from . import PluginTestCase

here = Path(__file__).parent


class CheckNoSolutionTestCase(PluginTestCase):
    def test_ok(self):
        file1 = here / "test_files" / "nasl" / "21.04" / "test.nasl"
        text = file1.read_text(encoding=CURRENT_ENCODING)
        file1.write_text(
            text.replace(
                'name:"cvss_base", value:"0.0"', 'name:"cvss_base", value:"1.0"'
            ),
            encoding=CURRENT_ENCODING,
        )
        context = MagicMock()
        context.nasl_files = [file1]
        context.root = here
        plugin = CheckNoSolution(context)
        results = list(plugin.run())

        self.assertEqual(len(results), 0)
        file1.write_text(text, encoding=CURRENT_ENCODING)

    def test_ok_no_score(self):
        file1 = here / "test_files" / "nasl" / "21.04" / "test.nasl"
        context = MagicMock()
        context.nasl_files = [file1]
        context.root = here
        plugin = CheckNoSolution(context)
        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_solution_type(self):
        file1 = (
            here
            / "test_files"
            / "nasl"
            / "21.04"
            / "fail_solution_template.nasl"
        )
        text = file1.read_text(encoding=CURRENT_ENCODING)
        file1.write_text(
            text.replace("NoneAvailable", "WillNotFix"),
            encoding=CURRENT_ENCODING,
        )
        context = MagicMock()
        context.nasl_files = [file1]
        context.root = here
        plugin = CheckNoSolution(context)
        results = list(plugin.run())

        self.assertEqual(len(results), 0)
        file1.write_text(text, encoding=CURRENT_ENCODING)

    def test_ok_inc(self):
        file1 = here / "test_files" / "nasl" / "21.04" / "test.inc"

        context = MagicMock()
        context.nasl_files = [file1]
        context.root = here
        plugin = CheckNoSolution(context)
        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_too_old_1_year(self):
        file1 = (
            here
            / "test_files"
            / "nasl"
            / "21.04"
            / "fail_solution_template.nasl"
        )
        context = MagicMock()
        context.nasl_files = [file1]
        context.root = here
        plugin = CheckNoSolution(context)
        results = list(plugin.run())

        from_root = get_path_from_root(file1, context.root)

        self.assertEqual(len(results), 5)
        self.assertIsInstance(results[0], LinterWarning)
        self.assertIn(
            f"{from_root}: ",
            results[0].message,
        )
        self.assertIn(
            "Missing solution, older than 1 year.",
            results[0].message,
        )

    def test_too_old_6_months(self):
        file1 = (
            here
            / "test_files"
            / "nasl"
            / "21.04"
            / "fail_solution_template.nasl"
        )
        new_date = (datetime.now() - timedelta(days=200)).strftime("%Y/%m/%d")

        text = file1.read_text(encoding=CURRENT_ENCODING)
        file1.write_text(
            text.replace("02nd February, 2021", new_date),
            encoding=CURRENT_ENCODING,
        )

        context = MagicMock()
        context.nasl_files = [file1]
        context.root = here
        plugin = CheckNoSolution(context)
        results = list(plugin.run())

        # reverse change to file
        file1.write_text(text, encoding=CURRENT_ENCODING)
        from_root = get_path_from_root(file1, context.root)

        self.assertEqual(len(results), 5)
        self.assertIsInstance(results[0], LinterWarning)
        self.assertIn(
            f"{from_root}: ",
            results[0].message,
        )
        self.assertIn(
            "Missing solution, older than 6 months.",
            results[0].message,
        )

    def test_too_young_31_days(self):
        file1 = (
            here
            / "test_files"
            / "nasl"
            / "21.04"
            / "fail_solution_template.nasl"
        )
        new_date = (datetime.now() - timedelta(days=10)).strftime("%Y/%m/%d")

        text = file1.read_text(encoding=CURRENT_ENCODING)
        file1.write_text(
            text.replace("02nd February, 2021", new_date),
            encoding=CURRENT_ENCODING,
        )

        context = MagicMock()
        context.nasl_files = [file1]
        context.root = here
        plugin = CheckNoSolution(context)
        results = list(plugin.run())

        # reverse change to file
        file1.write_text(text, encoding=CURRENT_ENCODING)
        from_root = get_path_from_root(file1, context.root)

        self.assertEqual(len(results), 5)
        self.assertIsInstance(results[0], LinterWarning)
        self.assertIn(
            f"{from_root}: ",
            results[0].message,
        )
        self.assertIn(
            "Missing solution, but younger than 31 days.",
            results[0].message,
        )

    def test_multiples(self):
        file1 = (
            here
            / "test_files"
            / "nasl"
            / "21.04"
            / "fail_solution_template.nasl"
        )
        file2 = (
            here
            / "test_files"
            / "nasl"
            / "21.04"
            / "fail_solution_template2.nasl"
        )
        file3 = (
            here
            / "test_files"
            / "nasl"
            / "21.04"
            / "fail_solution_template3.nasl"
        )

        date1 = (datetime.now() - timedelta(days=200)).strftime("%Y/%m/%d")
        date2 = (datetime.now() - timedelta(days=400)).strftime("%Y/%m/%d")
        date3 = (datetime.now() - timedelta(days=10)).strftime("%Y/%m/%d")

        text = file1.read_text(encoding=CURRENT_ENCODING)

        file1.write_text(
            text.replace("02nd February, 2021", date1),
            encoding=CURRENT_ENCODING,
        )
        file2.write_text(
            text.replace("02nd February, 2021", date2),
            encoding=CURRENT_ENCODING,
        )
        file3.write_text(
            text.replace("02nd February, 2021", date3),
            encoding=CURRENT_ENCODING,
        )

        context = MagicMock()
        context.nasl_files = [file1, file2, file3]
        context.root = here
        plugin = CheckNoSolution(context)
        results = list(plugin.run())

        # reverse change to file
        file1.write_text(text, encoding=CURRENT_ENCODING)
        file2.unlink()
        file3.unlink()

        self.assertEqual(len(results), 7)
        self.assertEqual(
            "total missing solutions: 3",
            results[3].message,
        )
        self.assertEqual(
            "missing solutions younger 1 month: 1",
            results[4].message,
        )
        self.assertEqual(
            "missing solutions older than 6 months: 1",
            results[5].message,
        )
        self.assertEqual(
            "missing solutions older than 1 year: 1",
            results[6].message,
        )

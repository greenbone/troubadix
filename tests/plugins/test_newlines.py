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

import unittest

from naslinter.plugin import LinterWarning
from naslinter.plugins.newlines import CheckNewlines


class CheckNewlinesTestCase(unittest.TestCase):
    def test_ok(self):
        nasl_file = Path(__file__).parent / "test_files" / "test.nasl"
        lines = nasl_file.read_text(encoding="latin1").split("\n")

        results = list(CheckNewlines.run(nasl_file, lines))
        self.assertEqual(len(results), 0)

    def test_newline_in_name(self):
        nasl_file = Path(__file__).parent / "fail_name_newline.nasl"
        lines = nasl_file.read_text(encoding="latin1").splitlines()

        results = list(CheckNewlines.run(nasl_file, lines))

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterWarning)
        self.assertEqual(
            f"'{nasl_file}' contained a script_tag with an unallowed "
            "newline.\nRemoved the newline out of the following tag(s): "
            "script_name()",
            results[0].message,
        )

        new_lines = nasl_file.read_text(encoding="latin1")
        self.assertNotEqual(lines, new_lines)

        # revert changes for the next time
        nasl_file.write_text("\n".join(lines), encoding="latin1")

    def test_newline_in_name_and_copyright(self):
        nasl_file = (
            Path(__file__).parent
            / "test_files"
            / "fail_name_and_copyright_newline.nasl"
        )
        lines = nasl_file.read_text(encoding="latin1").splitlines()

        results = list(CheckNewlines.run(nasl_file, lines))

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterWarning)
        self.assertEqual(
            f"'{nasl_file}' contained a script_tag with an unallowed "
            "newline.\nRemoved the newline out of the following tag(s): "
            "script_name() script_copyright()",
            results[0].message,
        )

        new_lines = nasl_file.read_text(encoding="latin1")
        self.assertNotEqual(lines, new_lines)

        # revert changes for the next time
        nasl_file.write_text("\n".join(lines), encoding="latin1")

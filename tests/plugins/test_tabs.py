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

from troubadix.plugin import LinterWarning
from troubadix.plugins.tabs import TAB_TO_SPACES, CheckTabs

from . import PluginTestCase


class CheckTabsTestCase(PluginTestCase):
    def test_ok(self):
        path = Path("tests/file.nasl")
        content = "What ever."

        results = list(
            CheckTabs.run(
                path,
                content,
            )
        )

        self.assertEqual(len(results), 0)

    def test_with_tabs(self):
        path = Path("tests/file.nasl")

        path.write_text(
            "\t\t\t\t\t\t\n1234456789",
            encoding="utf-8",
        )
        content = path.read_text(encoding="latin1")

        expected_content = "            \n1234456789"

        results = list(
            CheckTabs.run(
                path,
                content,
            )
        )
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterWarning)
        self.assertEqual(
            f"Replaced one or more tabs to {TAB_TO_SPACES} spaces!",
            results[0].message,
        )
        self.assertEqual(
            path.read_text(encoding="latin1"),
            expected_content,
        )

        if path.exists():
            path.unlink()

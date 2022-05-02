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

from troubadix.plugin import LinterError
from troubadix.plugins.tabs import CheckTabs

from . import PluginTestCase


class CheckTabsTestCase(PluginTestCase):
    def test_ok(self):
        path = Path("tests/file.nasl")
        content = "What ever."
        fake_context = self.create_file_plugin_context(
            nasl_file=path, lines=content.splitlines()
        )
        plugin = CheckTabs(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_with_tabs(self):
        path = Path("tests/file.nasl")

        content = "\t\t\t\t\t\t\n1234456789"

        fake_context = self.create_file_plugin_context(
            nasl_file=path, lines=content.splitlines()
        )
        plugin = CheckTabs(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            results[0].message,
            "VT uses tabs instead of spaces.",
        )
        self.assertEqual(results[0].line, 1)

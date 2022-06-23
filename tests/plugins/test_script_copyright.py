# Copyright (C) 2021 Greenbone Networks GmbH
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
from troubadix.plugins.script_copyright import CheckScriptCopyright

from . import PluginTestCase


class CheckScriptCopyrightTestCase(PluginTestCase):
    def test_copyright_ok(self):
        path = Path("some/file.nasl")
        content = 'script_copyright("Copyright (C) 2020 Foo Bar")'
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckScriptCopyright(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_exclude_inc_file(self):
        path = Path("some/file.inc")
        fake_context = self.create_file_plugin_context(nasl_file=path)
        plugin = CheckScriptCopyright(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_copyright_error(self):
        path = Path("some/file.nasl")
        content = 'script_copyright("Copyright 2020 Foo Bar")'
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckScriptCopyright(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertIn(
            "The VT is using an incorrect syntax for its "
            "copyright statement.",
            results[0].message,
        )

    def test_copyright_error2(self):
        path = Path("some/file.nasl")
        content = (
            'script_copyright("This script is Copyright (C) 2020 Foo Bar")'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckScriptCopyright(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertIn(
            "The VT is using an incorrect syntax for its "
            "copyright statement.",
            results[0].message,
        )

    def test_copyright_error3(self):
        path = Path("some/file.nasl")
        content = 'script_copyright("Copyright (c) 2020 Foo Bar")'
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckScriptCopyright(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertIn(
            "The VT is using an incorrect syntax for its "
            "copyright statement.",
            results[0].message,
        )

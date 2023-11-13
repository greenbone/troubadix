# Copyright (C) 2022 Greenbone AG
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

from tests.plugins import PluginTestCase
from troubadix.plugin import LinterError
from troubadix.plugins.script_xref_form import CheckScriptXrefForm


class CheckScriptXrefFormTestCase(PluginTestCase):
    path = Path("some/file.nasl")

    def test_ok(self):
        content = (
            '  script_xref(name: "foo", value:"bar");\n'
            '  script_tag(name: "foo"'
            ", value:'foobar');\n"
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptXrefForm(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_exclude_inc_file(self):
        path = Path("some/file.inc")
        fake_context = self.create_file_plugin_context(nasl_file=path)
        plugin = CheckScriptXrefForm(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_wrong_name(self):
        content = '  script_xref(nammmme: "foo", value:"bar");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptXrefForm(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            'script_xref(nammmme: "foo", value:"bar");: does not conform to'
            ' script_xref(name:"<name>", value:<value>);',
            results[0].message,
        )

    def test_wrong_value(self):
        content = '  script_xref(name: "foo", valueeeee:"bar");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptXrefForm(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)

    def test_wrong_missing_parameters(self):
        content = '  script_xref("foo", "bar");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptXrefForm(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)

    def test_wrong_missing_name_parameter(self):
        content = '  script_xref("foo", value:"bar");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptXrefForm(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)

    def test_wrong_missing_value_parameter(self):
        content = '  script_xref(name:"foo", "bar");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptXrefForm(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)

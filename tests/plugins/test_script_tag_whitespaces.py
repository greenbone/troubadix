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
from troubadix.plugins.script_tag_whitespaces import CheckScriptTagWhitespaces


class CheckScriptTagWhitespacesTestCase(PluginTestCase):
    path = Path("some/file.nasl")

    def test_ok(self):
        content = (
            '  script_name("MyProduct Multiple Vulnerabilities");\n'
            '  script_tag(name:"summary", value:"foo\nbar");\n'
            '  script_tag(name:"insight", value:"bar foo");\n'
            '  script_tag(name:"impact", value:"- foo\n  - bar");\n'
            '  script_tag(name:"affected", value:"foo\n  bar");\n'
            '  script_xref(name:"foo1", value:"foo\nbar");\n'
            '  script_xref(name:"foo2", value:"bar foo");\n'
            '  script_xref(name:"foo3", value:"- foo\n  - bar");\n'
            '  script_xref(name:"foo4", value:"foo\n  bar");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptTagWhitespaces(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_exclude_inc_file(self):
        path = Path("some/file.inc")
        fake_context = self.create_file_plugin_context(nasl_file=path)
        plugin = CheckScriptTagWhitespaces(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_script_tag_leading_whitespace(self):
        content = '  script_tag(name:"insight", value:" bar");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptTagWhitespaces(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            'script_tag(name:"insight", value:" bar");: value contains a'
            " leading or trailing whitespace character",
            results[0].message,
        )

    def test_script_name_leading_whitespace(self):
        content = '  script_name(" MyProduct Multiple Vulnerabilities");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptTagWhitespaces(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            'script_name(" MyProduct Multiple Vulnerabilities");: value'
            " contains a leading or trailing whitespace character",
            results[0].message,
        )

    def test_script_xref_leading_whitespace(self):
        content = '  script_xref(name:"foo", value:" bar");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptTagWhitespaces(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            'script_xref(name:"foo", value:" bar");: value contains a'
            " leading or trailing whitespace character",
            results[0].message,
        )

    def test_script_tag_trailing_whitespace(self):
        content = '  script_tag(name:"insight", value:"bar ");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptTagWhitespaces(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)

    def test_script_name_trailing_whitespace(self):
        content = '  script_name("MyProduct Multiple Vulnerabilities ");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptTagWhitespaces(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)

    def test_script_xref_trailing_whitespace(self):
        content = '  script_xref(name:"foo", value:"bar ");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptTagWhitespaces(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            'script_xref(name:"foo", value:"bar ");: value contains a'
            " leading or trailing whitespace character",
            results[0].message,
        )

    # nb: The script_name() tag is not allowed to contain newlines (checked in a
    # dedicated plugin) so no specific test cases have been added here.
    def test_script_tag_trailing_newline(self):
        content = '  script_tag(name:"insight", value:"bar\n");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptTagWhitespaces(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)

    def test_script_tag_trailing_newline_with_space(self):
        content = '  script_tag(name:"insight", value:"foo bar\n");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptTagWhitespaces(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)

    def test_script_tag_trailing_newline_with_newline(self):
        content = '  script_tag(name:"insight", value:"foo\nbar\n");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptTagWhitespaces(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)

    def test_script_tag_trailing_newline_with_newline_and_spaces(self):
        content = '  script_tag(name:"insight", value:"foo\n  bar\n");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptTagWhitespaces(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)

    # nb: The value of script_xref(name:"URL" are also checked separately in
    # script_xref_url() and that one would also report trailing / leading
    # newlines and similar for that specific case
    def test_script_xref_trailing_newline(self):
        content = '  script_xref(name:"foo", value:"bar\n");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptTagWhitespaces(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)

    def test_script_xref_trailing_newline_with_space(self):
        content = '  script_xref(name:"foo", value:"foo bar\n");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptTagWhitespaces(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)

    def test_script_xref_trailing_newline_with_newline(self):
        content = '  script_xref(name:"foo", value:"foo\nbar\n");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptTagWhitespaces(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)

    def test_script_xref_trailing_newline_with_newline_and_spaces(self):
        content = '  script_xref(name:"foo", value:"foo\n  bar\n");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptTagWhitespaces(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)

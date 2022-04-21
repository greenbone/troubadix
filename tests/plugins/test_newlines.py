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

from troubadix.helper import CURRENT_ENCODING
from troubadix.plugin import LinterError
from troubadix.plugins.newlines import CheckNewlines

from . import PluginTestCase


class CheckNewlinesTestCase(PluginTestCase):
    def test_ok(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = nasl_file.read_text(encoding=CURRENT_ENCODING)
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckNewlines(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_newline_in_name(self):
        nasl_file = (
            Path(__file__).parent / "test_files" / "fail_name_newline.nasl"
        )
        content = nasl_file.read_text(encoding=CURRENT_ENCODING)
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckNewlines(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "Found a newline within the tag script_name.",
            results[0].message,
        )

    def test_newline_in_name_and_copyright(self):
        nasl_file = (
            Path(__file__).parent
            / "test_files"
            / "fail_name_and_copyright_newline.nasl"
        )
        content = nasl_file.read_text(encoding=CURRENT_ENCODING)
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckNewlines(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "Found a newline within the tag script_name.",
            results[0].message,
        )
        self.assertIsInstance(results[1], LinterError)
        self.assertEqual(
            "Found a newline within the tag script_copyright.",
            results[1].message,
        )

    def test_whitespaces_in_name_and_copyright(self):
        nasl_file = (
            Path(__file__).parent
            / "test_files"
            / "fail_name_and_copyright_newline.nasl"
        )
        content = (
            'script_name( "foodetection");\n'
            'script_copyright ( "Copyright(c) Greenbone Networks GmbH" ) ; \n'
            'script_copyright ("Copyright(c) Greenbone Networks GmbH");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckNewlines(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "Found whitespaces in script_name.",
            results[0].message,
        )
        self.assertIsInstance(results[1], LinterError)
        self.assertEqual(
            "Found whitespaces in script_copyright.",
            results[1].message,
        )

    def test_new_line(self):
        nasl_file = (
            Path(__file__).parent / "test_files" / "fail_bad_new_line.nasl"
        )
        content = (
            'script_name("foo detection");'
            'script_copyright("Copyright(c) Greenbone Networks GmbH");\r\n'
            'script_copyright("Copyrigh(c) Greenbone Networks GmbH");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckNewlines(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "Found \\r or \\r\\n newline.",
            results[0].message,
        )
        self.assertIsInstance(results[0], LinterError)

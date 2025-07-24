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

from troubadix.plugin import LinterError, LinterWarning
from troubadix.plugins.using_display import CheckUsingDisplay

from . import PluginTestCase


class CheckUsingDisplayTestCase(PluginTestCase):
    def test_ok(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"cvss_base_vector", '
            'value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckUsingDisplay(fake_context)

        results = list(plugin.run())

        self.assertEqual(0, len(results))

    def test_using_display(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"cvss_base_vector", '
            'value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");\n'
            '  display("FOO");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckUsingDisplay(fake_context)

        results = list(plugin.run())

        self.assertEqual(1, len(results))
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            'VT is using a display() without any if statement at line 3: display("FOO");',
            results[0].message,
        )

    def test_using_if_display(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"cvss_base_vector", '
            'value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");\n'
            'if (0) display("FOO");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckUsingDisplay(fake_context)

        results = list(plugin.run())

        self.assertEqual(1, len(results))
        self.assertIsInstance(results[0], LinterWarning)
        self.assertIn(
            "VT is using a display() inside an if statement but without debug check",
            results[0].message,
        )
        self.assertIn('if (0) display("FOO");', results[0].message)

    def test_using_comment_display(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"cvss_base_vector", '
            'value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");\n'
            '# display("FOO");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckUsingDisplay(fake_context)

        results = list(plugin.run())

        # Comments are removed, so display() won't be found
        self.assertEqual(0, len(results))

    def test_using_debug_if_display(self):
        """Test that display() inside a debug if statement is allowed"""
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            'if (debug) display("FOO");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckUsingDisplay(fake_context)

        results = list(plugin.run())

        # Should be OK because it's in a debug if
        self.assertEqual(0, len(results))

    def test_display_in_string_ignored(self):
        path = Path("some/file.nasl")
        content = "str = 'display(\"FOO\")';\n"
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckUsingDisplay(fake_context)

        results = list(plugin.run())

        self.assertEqual(0, len(results))

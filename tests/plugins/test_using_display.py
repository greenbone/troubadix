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

from troubadix.plugin import LinterError, LinterWarning
from troubadix.plugins.using_display import CheckUsingDisplay

from . import PluginTestCase


class CheckUsingDisplayTestCase(PluginTestCase):
    def test_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"cvss_base_vector", '
            'value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckUsingDisplay(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_using_display(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"cvss_base_vector", '
            'value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");\n'
            'display("FOO");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckUsingDisplay(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            'VT/Include is using a display() function at: display("FOO");',
            results[0].message,
        )

    def test_using_if_display(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"cvss_base_vector", '
            'value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");\n'
            'if (0) display("FOO");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckUsingDisplay(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterWarning)
        self.assertEqual(
            "VT is using a display() function which is "
            "protected by a comment or an if statement at: "
            'if (0) display("FOO");.',
            results[0].message,
        )

    def test_using_comment_display(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"cvss_base_vector", '
            'value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");\n'
            '# display("FOO");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckUsingDisplay(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterWarning)
        self.assertEqual(
            "VT is using a display() function which is "
            "protected by a comment or an if statement at: "
            '# display("FOO");.',
            results[0].message,
        )

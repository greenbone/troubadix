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
from unittest.mock import MagicMock

from troubadix.plugin import LinterError
from troubadix.plugins.duplicated_script_tags import CheckDuplicatedScriptTags

from . import PluginTestCase


class CheckDuplicatedScriptTagsTestCase(PluginTestCase):
    def test_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"cvss_base_vector", '
            'value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");'
        )
        fake_context = MagicMock()
        fake_context.nasl_file = path
        fake_context.file_content = content
        plugin = CheckDuplicatedScriptTags(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_duplicated_function(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_name("Foo Bar");\n'
            'script_name("Foo Bar");\n'
        )
        fake_context = MagicMock()
        fake_context.nasl_file = path
        fake_context.file_content = content
        plugin = CheckDuplicatedScriptTags(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "The VT is using the script tag "
            "'script_name' multiple number of times.",
            results[0].message,
        )

    def test_duplicated_tag(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"cvss_base", value:"5.0");\n'
        )
        fake_context = MagicMock()
        fake_context.nasl_file = path
        fake_context.file_content = content
        plugin = CheckDuplicatedScriptTags(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "The VT is using the script tag "
            "'cvss_base' multiple number of times.",
            results[0].message,
        )

    def test_excluded_tag(self):
        path = Path("some/file.nasl")
        content = (
            'script_add_preference(name:"Test", type:"checkbox");\n'
            'script_add_preference(name:"Test2", type:"checkbox");\n'
        )
        fake_context = MagicMock()
        fake_context.nasl_file = path
        fake_context.file_content = content
        plugin = CheckDuplicatedScriptTags(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

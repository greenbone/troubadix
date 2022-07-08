#  Copyright (c) 2022 Greenbone Networks GmbH
#
#  SPDX-License-Identifier: GPL-3.0-or-later
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

from pathlib import Path

from tests.plugins import PluginTestCase
from troubadix.helper import CURRENT_ENCODING
from troubadix.plugin import LinterError, LinterFix
from troubadix.plugins.script_version_and_last_modification_tags import (
    CheckScriptVersionAndLastModificationTags,
)


class CheckScriptVersionAndLastModificationTagsTestCase(PluginTestCase):
    def test_ok(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
            'script_version("2021-07-19T12:32:02+0000");\n'
            'script_tag(name: "last_modification", value: "2021-07-19 '
            '12:32:02 +0000 (Mon, 19 Jul 2021)");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckScriptVersionAndLastModificationTags(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_exclude_inc_file(self):
        path = Path("some/file.inc")
        fake_context = self.create_file_plugin_context(nasl_file=path)
        plugin = CheckScriptVersionAndLastModificationTags(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_old_ok(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
            'script_version("$Revision: 12345 $");\n'
            'script_tag(name: "last_modification", value: "$Date: 2021-07-19 '
            '12:32:02 +0000 (Mon, 19 Jul 2021) $");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckScriptVersionAndLastModificationTags(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_missing_script_version(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckScriptVersionAndLastModificationTags(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT is missing script_version();.",
            results[0].message,
        )

    def test_fix_last_modification_date(self):
        with self.create_directory() as testdir:
            nasl_file = testdir / "test.nasl"
            content = (
                'script_version("12345");\n'
                'script_tag(name: "last_modification", '
                'value: "2021/07/19");\n'
            )
            nasl_file.write_text(content, encoding=CURRENT_ENCODING)
            fake_context = self.create_file_plugin_context(
                nasl_file=nasl_file, file_content=content
            )

            plugin = CheckScriptVersionAndLastModificationTags(fake_context)

            results = list(plugin.run())

            self.assertEqual(len(results), 2)

            results = list(plugin.fix())

            self.assertEqual(len(results), 1)
            self.assertIsInstance(results[0], LinterFix)

            new_content = nasl_file.read_text(encoding=CURRENT_ENCODING)
            self.assertNotEqual(content, new_content)

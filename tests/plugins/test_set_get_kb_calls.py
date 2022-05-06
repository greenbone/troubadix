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
from troubadix.plugin import LinterError
from troubadix.plugins.set_get_kb_calls import CheckWrongSetGetKBCalls


class CheckWrongSetGetKBCallTestCase(PluginTestCase):
    def test_ok(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            'set_kb_item(name:"kb/key", value:"value");\n'
            'replace_kb_item(name:"kb/key", value:"value");\n'
            'get_kb_item("kb/key");\n'
            'get_kb_list("kb/key");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckWrongSetGetKBCalls(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_nok(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            'set_kb_item("kbkey", value:"value");\n'
            'replace_kb_item(name:"kbkey", "value");\n'
            'replace_kb_item(name:"kbkey");\n'
            'replace_kb_item(name:"kbkey", name:"kbkey");\n'
            'get_kb_item(name:"kbkey");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckWrongSetGetKBCalls(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 4)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "The VT/Include is missing a 'name:' and/or 'value:' parameter: "
            'set_kb_item("kbkey", value:"value");',
            results[0].message,
        )
        self.assertEqual(
            "The VT/Include is missing a 'name:' and/or 'value:' parameter: "
            'replace_kb_item(name:"kbkey", "value");',
            results[1].message,
        )
        self.assertEqual(
            "The VT/Include is missing a 'name:' and/or 'value:' parameter: "
            'replace_kb_item(name:"kbkey");',
            results[2].message,
        )
        self.assertEqual(
            "The VT/Include is using a non-existent 'name:' and/or "
            "'value:' parameter: get_kb_item(name:\"kbkey\");",
            results[3].message,
        )

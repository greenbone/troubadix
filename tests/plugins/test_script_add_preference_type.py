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

from troubadix.plugin import LinterError
from troubadix.plugins.script_add_preference_type import (
    VALID_TYPES,
    CheckScriptAddPreferenceType,
    ValidType,
)

from . import PluginTestCase


class CheckScriptAddPreferenceTypeTestCase(PluginTestCase):
    def test_ok(self):
        for pref_type in ValidType:
            path = Path("some/file.nasl")
            content = (
                '  script_tag(name:"cvss_base", value:"4.0");\n'
                '  script_tag(name:"cvss_base_vector", \n'
                'value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");\n'
                f'  script_add_preference(type: "{pref_type.value}");\n'
            )
            fake_context = self.create_file_plugin_context(
                nasl_file=path, file_content=content
            )
            plugin = CheckScriptAddPreferenceType(fake_context)

            results = list(plugin.run())

            self.assertEqual(len(results), 0)

    def test_exclude_inc_file(self):
        path = Path("some/file.inc")
        fake_context = self.create_file_plugin_context(nasl_file=path)
        plugin = CheckScriptAddPreferenceType(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_no_add_preference(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"cvss_base_vector", '
            'value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckScriptAddPreferenceType(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_invalid(self):
        add_pref = 'script_add_preference(type: "invalid");'
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_name("Foo Bar");\n'
            '  script_name("Foo Bar");\n'
            f"{add_pref}\n"
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckScriptAddPreferenceType(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT is using an invalid or misspelled type "
            f"(invalid) in {add_pref} \n"
            f"Allowed are: {sorted(VALID_TYPES)}",
            results[0].message,
        )

    def test_invalid_with_parameters_order(self):
        add_pref = (
            'script_add_preference(name:"File or Directory Name", '
            'type:"string", value:"/home", id:1);'
        )
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_name("Foo Bar");\n'
            f"{add_pref}\n"
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckScriptAddPreferenceType(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT is using an invalid or misspelled type "
            f"(string) in {add_pref} \n"
            f"Allowed are: {sorted(VALID_TYPES)}",
            results[0].message,
        )

    def test_missing_type(self):
        add_pref = 'script_add_preference(name:"File or Directory Name", value:"/home", id:1);'
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_name("Foo Bar");\n'
            f"{add_pref}\n"
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckScriptAddPreferenceType(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            f"script_add_preference call is missing a 'type' parameter in '{add_pref}'",
            results[0].message,
        )

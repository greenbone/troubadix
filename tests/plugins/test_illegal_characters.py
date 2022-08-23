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
from troubadix.plugins.illegal_characters import CheckIllegalCharacters

from . import PluginTestCase


class CheckIllegalCharactersTestCase(PluginTestCase):
    def test_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckIllegalCharacters(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_exclude_inc_file(self):
        path = Path("some/file.inc")
        fake_context = self.create_file_plugin_context(nasl_file=path)
        plugin = CheckIllegalCharacters(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_illegal_chars_in_various_tags(self):
        tags = [
            "summary",
            "impact",
            "affected",
            "insight",
            "vuldetect",
            "solution",
        ]
        path = Path("tests/file.nasl")
        for tag in tags:
            content = (
                'script_tag(name:"cvss_base", value:"4.0");\n'
                f'script_tag(name:"{tag}", value:"Foo|Bar;Baz=Bad.");\n'
                'script_tag(name:"solution_type", value:"VendorFix");\n'
                'script_tag(name:"solution", value:"meh");\n'
            )

            fake_context = self.create_file_plugin_context(
                nasl_file=path, file_content=content
            )
            plugin = CheckIllegalCharacters(fake_context)

            results = list(plugin.run())

            self.assertEqual(len(results), 3)
            self.assertIsInstance(results[0], LinterError)
            self.assertIsInstance(results[1], LinterError)
            self.assertIsInstance(results[2], LinterWarning)
            self.assertEqual(
                results[0].message,
                f"Found illegal character '|' "
                f'in script_tag(name:"{tag}", '
                'value:"Foo|Bar;Baz=Bad.");',
            )
            self.assertEqual(
                results[1].message,
                f"Found illegal character ';' "
                f'in script_tag(name:"{tag}", '
                'value:"Foo|Bar;Baz=Bad.");',
            )
            self.assertEqual(
                results[2].message,
                f"Found illegal character '=' "
                f'in script_tag(name:"{tag}", '
                'value:"Foo|Bar;Baz=Bad.");',
            )

    def test_fix_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo | Bar ; Baz = Test");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckIllegalCharacters(fake_context)

        results = list(plugin.run())

        fixed_content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo <pipe> Bar , Baz = Test");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
        )

        self.assertEqual(len(results), 3)
        self.assertIsInstance(results[0], LinterError)
        self.assertIsInstance(results[1], LinterError)
        self.assertIsInstance(results[2], LinterWarning)
        self.assertEqual(plugin.new_file_content, fixed_content)

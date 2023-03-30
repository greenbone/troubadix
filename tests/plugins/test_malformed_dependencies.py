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
from troubadix.plugins.malformed_dependencies import CheckMalformedDependencies

from . import PluginTestCase

here = Path(__file__).parent


class CheckMalformedDependenciesTestCase(PluginTestCase):
    def test_ok(self):
        path = here / "file.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_dependencies("example.nasl", "example2.nasl");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content, root=here
        )
        plugin = CheckMalformedDependencies(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_nok_1(self):
        path = here / "file.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_dependencies("example.nasl,example2.nasl");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content, root=here
        )
        plugin = CheckMalformedDependencies(fake_context)

        results = list(plugin.run())

        expected_result = (
            "The script dependency value is malformed and contains a "
            "comma in the dependency value: 'example.nasl,example2.nasl'"
        )

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(results[0].message, expected_result)

    def test_nok_2(self):
        path = here / "file.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_dependencies("example.nasl,example2.nasl",'
            ' "example3.nasl");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content, root=here
        )
        plugin = CheckMalformedDependencies(fake_context)

        results = list(plugin.run())

        expected_result = (
            "The script dependency value is malformed and contains a "
            "comma in the dependency value: 'example.nasl,example2.nasl'"
        )

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(results[0].message, expected_result)

    def test_nok_3(self):
        path = here / "file.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_dependencies("example.nasl example2.nasl");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content, root=here
        )
        plugin = CheckMalformedDependencies(fake_context)

        results = list(plugin.run())

        expected_result = (
            "The script dependency value is malformed and contains "
            "whitespace within the dependency value: "
            "'example.nasl example2.nasl'"
        )

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(results[0].message, expected_result)

    def test_nok_4(self):
        path = here / "file.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_dependencies("example.nasl, example2.nasl");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content, root=here
        )
        plugin = CheckMalformedDependencies(fake_context)

        results = list(plugin.run())

        expected_result_1 = (
            "The script dependency value is malformed and contains "
            "a comma in the dependency value: 'example.nasl, example2.nasl'"
        )

        expected_result_2 = (
            "The script dependency value is malformed and contains "
            "whitespace within the dependency value: "
            "'example.nasl, example2.nasl'"
        )

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], LinterError)
        self.assertIsInstance(results[1], LinterError)
        self.assertEqual(results[0].message, expected_result_1)
        self.assertEqual(results[1].message, expected_result_2)

    def test_nok_5(self):
        path = here / "file.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_dependencies("example .nasl", "example2.nasl");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content, root=here
        )
        plugin = CheckMalformedDependencies(fake_context)

        results = list(plugin.run())

        expected_result = (
            "The script dependency value is malformed and contains "
            "whitespace within the dependency value: 'example .nasl'"
        )

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(results[0].message, expected_result)

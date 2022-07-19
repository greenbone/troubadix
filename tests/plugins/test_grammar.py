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

from troubadix.plugin import LinterError
from troubadix.plugins.grammar import CheckGrammar

from . import PluginTestCase


class CheckNewlinesTestCase(PluginTestCase):
    def test_ok(self):
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
        plugin = CheckGrammar(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_grammar(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
            "# is prone to a security bypass vulnerabilities\n"
        )

        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckGrammar(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT/Include has the following grammar problem: "
            "# is prone to a security bypass vulnerabilities",
            results[0].message,
        )

    def test_grammar2(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
            "# is prone to a security bypass vulnerabilities\n"
            "# refer the Reference\n"
        )

        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckGrammar(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT/Include has the following grammar problem: "
            "# is prone to a security bypass vulnerabilities",
            results[0].message,
        )

        self.assertIsInstance(results[1], LinterError)
        self.assertEqual(
            "VT/Include has the following grammar problem: "
            "# refer the Reference",
            results[1].message,
        )

    def test_grammar3(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
            'script_tag(name:"summary", value:"Adobe Digital Edition is prone '
            'a to denial of service (DoS) vulnerability.");\n'
        )

        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckGrammar(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT/Include has the following grammar problem: "
            'script_tag(name:"summary", value:"Adobe Digital Edition is prone '
            'a to denial of service (DoS) vulnerability.");',
            results[0].message,
        )

    def test_grammar4(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
            'script_tag(name:"summary", value:"Splunk Enterprise is prone an '
            'open redirect vulnerability.");\n'
        )

        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckGrammar(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT/Include has the following grammar problem: "
            'script_tag(name:"summary", value:"Splunk Enterprise is prone an '
            'open redirect vulnerability.");',
            results[0].message,
        )

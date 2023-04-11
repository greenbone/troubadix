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
from troubadix.plugins.deprecated_functions import CheckDeprecatedFunctions

from . import PluginTestCase


class CheckDeprecatedDependencyTestCase(PluginTestCase):
    def test_ok(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            "  script_category(ACT_ATTACK);\n"
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckDeprecatedFunctions(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_ok_comment(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            "  script_category(ACT_ATTACK);\n"
            "# nb: script_summary() is deprecated\n"
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckDeprecatedFunctions(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_deprecated_functions(self):
        deprecated_output = {
            'script_summary();, use script_tag(name:"'
            'summary", value:""); instead': "  script_"
            'summary("deprecated");',
            "script_id();, use script_oid(); with "
            "the full OID instead": "  script_id(123345);",
            "security_note();": '  security_note("deprecated");',
            "security_warning();": '  security_warning("deprecated");',
            "security_hole();": '  security_hole("deprecated");',
            "script_description();": '  script_description("deprecated");',
            'script_tag(name:"risk_factor", value:"SEVERITY");': "  script_"
            'tag(name:"risk_factor", value:"Critical");',
            "script_bugtraq_id();": "  script_bugtraq_id(123);",
        }
        path = Path("some/file.nasl")
        for msg, cont in deprecated_output.items():
            content = (
                '  script_tag(name:"cvss_base", value:"4.0");\n'
                '  script_tag(name:"summary", value:"Foo Bar.");\n'
                f"  script_category(ACT_ATTACK);\n{cont}\n"
            )
            fake_context = self.create_file_plugin_context(
                nasl_file=path, file_content=content
            )
            plugin = CheckDeprecatedFunctions(fake_context)

            results = list(plugin.run())

            self.assertEqual(len(results), 1)
            self.assertIsInstance(results[0], LinterError)
            self.assertEqual(
                f"Found a deprecated function call / description item: {msg}",
                results[0].message,
            )

    def test_nok_newline(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            "  script_category(ACT_ATTACK);\n"
            '  script_summary("With\nnewline");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckDeprecatedFunctions(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "Found a deprecated function call / description item: "
            'script_summary();, use script_tag(name:"summary", value:""); '
            "instead",
            results[0].message,
        )

#  Copyright (c) 2022 Greenbone AG
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

from troubadix.plugin import LinterError, LinterWarning
from troubadix.plugins.log_messages import CheckLogMessages

from . import PluginTestCase


class CheckLogMessagesTestCase(PluginTestCase):
    def test_ok(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"0.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            '  log_message("hello test");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckLogMessages(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_nok(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            "\n"
            "  log_message( port:port, data:'The remote SSL/TLS server is using"
            " the following certificate(s) with a ECC key with less than ' + "
            "min_key_size + ' bits (key-size:algorithm:serial:issuer):\n' + "
            "report); \n\n"
            "  log_message(port2:port2, data:'The remote SSL/TLS server is "
            "using "
            "the following certificate(s) with a ECC key with less than ' + "
            "min_key_size2 + ' bits (key-size:algorithm:serial:issuer):\n' + "
            "report );\n\n"
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckLogMessages(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterWarning)
        self.assertEqual(
            "The VT is using a log_message in a VT with a severity",
            results[0].message,
        )

    def test_nok2(self):
        nasl_file = Path(__file__).parent / "test2.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            "  log_message('The remote SSL/TLS server is using "
            "the following certificate(s) with a ECC key with less than ' + "
            "min_key_size + ' bits (key-size:algorithm:serial:issuer)');"
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckLogMessages(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterWarning)
        self.assertEqual(
            "The VT is using a log_message in a VT with a severity",
            results[0].message,
        )

    def test_nok3(self):
        nasl_file = Path(__file__).parent / "test2.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            "  log_message(  );"
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckLogMessages(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "The VT is using an empty log_message() function",
            results[0].message,
        )
        self.assertEqual(
            "The VT is using a log_message in a VT with a severity",
            results[1].message,
        )

    def test_nok4(self):
        nasl_file = Path(__file__).parent / "test2.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            "  log_message(\t);\n"
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckLogMessages(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "The VT is using an empty log_message() function",
            results[0].message,
        )
        self.assertEqual(
            "The VT is using a log_message in a VT with a severity",
            results[1].message,
        )

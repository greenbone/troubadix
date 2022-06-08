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

from troubadix.plugin import LinterError
from troubadix.plugins.forking_nasl_functions import CheckForkingNaslFunctions

from . import PluginTestCase


class CheckForkingNaslFunctionsTestCase(PluginTestCase):
    def test_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
            'get_app_port_from_cpe_prefix("cpe:/o:foo:bar");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckForkingNaslFunctions(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_exclude_inc_file(self):
        path = Path("some/file.inc")
        fake_context = self.create_file_plugin_context(nasl_file=path)
        plugin = CheckForkingNaslFunctions(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_not_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
            "if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, "
            'service:"www" ) )\nexit( 0 );\n'
            "if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, "
            'service:"www" ) )\nexit( 0 );\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckForkingNaslFunctions(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "The VT is using the "
            'get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www" ) ) '
            "multiple times or in conjunction with other forking functions. "
            "Please either use get_app_port_from_list() from host_details.inc "
            "or split your VT into several VTs for each covered protocol.",
            results[0].message,
        )

    def test_not_ok2(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
            "if(!infos = get_app_full(cpe:CPE, port:port, exit_no_version:TRUE)"
            ")\nexit(0);\n"
            "if(!infos = get_app_full(cpe:CPE, port:port, exit_no_version:TRUE)"
            ")\nexit(0);\n"
        )

        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckForkingNaslFunctions(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "The VT is using the "
            "get_app_full(cpe:CPE, port:port, exit_no_version:TRUE)) "
            "multiple times or in conjunction with other forking functions. "
            "Please use e.g. get_app_version_and_location(), "
            "get_app_version_and_location_from_list() or similar functions "
            "from host_details.inc.",
            results[0].message,
        )

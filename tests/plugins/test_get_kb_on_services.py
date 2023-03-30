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

from troubadix.plugin import LinterError
from troubadix.plugins.get_kb_on_services import CheckGetKBOnServices

from . import PluginTestCase


class CheckGetKBOnServicesTestCase(PluginTestCase):
    def test_ok(self):
        path = Path("some/file.nasl")
        content = (
            '  script_oid("1.2.3.4.5.6.78909.8.7.000000");\n'
            '  script_tag(name:"cvss_base", value:"4.0");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckGetKBOnServices(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_exclude_inc_file(self):
        path = Path("some/file.inc")
        fake_context = self.create_file_plugin_context(nasl_file=path)
        plugin = CheckGetKBOnServices(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_ok_no_script_oid(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            'port = get_kb_item("Services/www");\n'
            'port = get_kb_list("Services/udp/upnp");\n'
        )

        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckGetKBOnServices(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], LinterError)

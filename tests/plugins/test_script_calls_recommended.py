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

from tests.plugins import PluginTestCase
from troubadix.plugin import LinterWarning
from troubadix.plugins.script_calls_recommended import (
    CheckScriptCallsRecommended,
)


class CheckScriptCallsRecommendedTestCase(PluginTestCase):
    path = Path("some/file.nasl")

    def test_ok(self):
        content = (
            "  script_dependencies();\n"
            "  script_require_ports();\n"
            "  script_require_udp_ports();\n"
            "  script_require_keys();\n"
            "  script_mandatory_keys();\n"
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptCallsRecommended(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_exclude_inc_file(self):
        path = Path("some/file.inc")
        fake_context = self.create_file_plugin_context(nasl_file=path)
        plugin = CheckScriptCallsRecommended(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_missing_calls(self):
        content = '  script_xref(name: "URL", value:"");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptCallsRecommended(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], LinterWarning)

    def test_dependencies_multiline(self):
        content = (
            # tests group1
            '  script_dependencies("123",\n"456");\n'
            # tests group2
            '  script_mandatory_keys("foo",\n"bar");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptCallsRecommended(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

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
from troubadix.plugins.solution_type import CheckSolutionType

from . import PluginTestCase


class CheckSolutionTypeTestCase(PluginTestCase):
    def test_ok(self):
        path = Path("some/file.nasl")
        content = 'script_tag(name:"cvss_base", value:"0.0");'
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSolutionType(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_exclude_inc_file(self):
        path = Path("some/file.inc")
        fake_context = self.create_file_plugin_context(nasl_file=path)
        plugin = CheckSolutionType(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_severity_present_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"1.0");'
            'script_tag(name:"solution_type", value:"Workaround");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSolutionType(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_no_solution_type(self):
        path = Path("some/file.nasl")
        content = 'script_tag(name:"cvss_base", value:"1.0");'
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSolutionType(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT does not contain a solution_type",
            results[0].message,
        )

    def test_wrong_solution_type(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"1.0");'
            'script_tag(name:"solution_type", value:"Wrong solution");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSolutionType(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT does not contain a valid solution_type 'value'",
            results[0].message,
        )

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
from troubadix.plugins.script_calls_mandatory import CheckScriptCallsMandatory
from tests.plugins import PluginTestCase


class CheckScriptCallsMandatoryTestCase(PluginTestCase):
    path = Path("some/file.nasl")

    def test_ok(self):

        content = (
            "script_name();\n"
            "script_version();\n"
            "script_category();\n"
            "script_family();\n"
            "script_copyright();\n"
        )

        results = list(
            CheckScriptCallsMandatory.run(
                nasl_file=self.path,
                file_content=content,
                tag_pattern=self.tag_pattern,
                special_tag_pattern=self.special_tag_pattern,
            )
        )
        self.assertEqual(len(results), 0)

    def test_missing_calls(self):
        content = 'script_xref(name: "URL", value:"");'

        results = list(
            CheckScriptCallsMandatory.run(
                nasl_file=self.path,
                file_content=content,
                tag_pattern=self.tag_pattern,
                special_tag_pattern=self.special_tag_pattern,
            )
        )
        self.assertEqual(len(results), 5)
        self.assertIsInstance(results[0], LinterError)

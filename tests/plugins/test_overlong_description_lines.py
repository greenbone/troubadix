#  Copyright (c) 2024 Greenbone AG
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

from tests.plugins import PluginTestCase
from troubadix.plugin import LinterError, LinterWarning
from troubadix.plugins.overlong_description_lines import (
    CheckOverlongDescriptionLines,
)


class CheckOverlongDescriptionLinesTestCase(PluginTestCase):
    def test_ok(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            "ignored line that is not part of description"
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
            "if (description)\n"
            "{\n"
            '  script_version("2021-09-02T14:01:33+0000");\n'
            '  script_name("name is ignored xxxxxxxxxxxxxxxxxxxxxxxxx'
            'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");\n'
            '  script_xref(name:"xref as well", value:"xxxxxxxxxxxxxx'
            'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");\n'
            '  script_add_preference(name:"script_add_preference as well '
            'xxxxxxxxxxxxxxxxxxxxxxx", type:"checkbox", value:"no", id:1);\n'
            '  script_add_preference(type:"password", value:"", id:2, name:"'
            'Another variant of script_add_preference xxxxxxxxxxxxxxxxxxxx");\n'
            'script_tag(name:"vuldetect", value:'
            '"Checks if a vulnerable version is present on the target host."'
            ");\n"
            "  exit(0);\n"
            "}\n"
            "ignored line that is not part of description"
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckOverlongDescriptionLines(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_line_too_long(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            "if (description)\n"
            "{\n"
            "  too long line xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
            '  script_tag(name:"vuldetect", value:'
            '"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"'
            ");\n"
            '  script_version("2021-09-02T14:01:33+0000");\n'
            "  exit(0);\n"
            "}\n"
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckOverlongDescriptionLines(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], LinterWarning)
        self.assertEqual(
            "Line 3 is too long with 102 characters. Max 100",
            results[0].message,
        )
        self.assertEqual(
            "Line 4 is too long with 102 characters. Max 100",
            results[1].message,
        )

    def test_no_description_start_found(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            "{\n"
            "  ignored too long line xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
            '  script_version("2021-09-02T14:01:33+0000");\n'
            "  exit(0);\n"
            "}\n"
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckOverlongDescriptionLines(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "Check failed. Unable to find start of description block",
            results[0].message,
        )

    def test_no_description_end_found(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            "if (description)\n"
            "{\n"
            "  ignored too long line xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
            '  script_version("2021-09-02T14:01:33+0000");\n'
            "}\n"
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckOverlongDescriptionLines(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "Check failed. Unable to find end of description block",
            results[0].message,
        )

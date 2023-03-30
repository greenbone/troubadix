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
from troubadix.plugins.solution_text import CheckSolutionText

from . import PluginTestCase

CORRECT_WILLNOTFIX_SUGGESTION = (
    "The VT with solution type 'WillNotFix' is using an incorrect syntax in "
    "the solution text. Please use one of these (EXACTLY):\n  "
    'script_tag(name:"solution", value:"No known solution was made available '
    "for at least one year\n  since the disclosure of this vulnerability. "
    "Likely none will be provided anymore. General solution\n  options are to "
    "upgrade to a newer release, disable respective features, remove the "
    'product or\n  replace the product by another one.");\n\n  '
    'script_tag(name:"solution", value:"No solution was made available by the '
    "vendor. General solution\n  options are to upgrade to a newer release, "
    "disable respective features, remove the product or\n  replace the product "
    'by another one.");\n\n  script_tag(name:"solution", value:"No solution '
    "was made available by the vendor.\n\n  Note: <add a specific note for the "
    'reason here>.");\n\n  script_tag(name:"solution", value:"No solution was '
    "made available by the vendor.\n\n  Vendor statement: <add specific vendor "
    'statement here>.");\n\n  script_tag(name:"solution", value:"No solution '
    "is required.\n\n  Note: <add a specific note for the reason here, e.g. "
    'CVE was disputed>.");'
)


class CheckSolutionTextTestCase(PluginTestCase):
    def test_ok(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"solution_type", value:"NoneAvailable");\n'
            '  script_tag(name:"solution", value:"No known solution is '
            "available as of 01st September, 2021.\n  Information "
            "regarding this issue will be updated once solution details "
            'are available.");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckSolutionText(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_ok2(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"solution_type", value:"WillNotFix");\n'
            '  script_tag(name:"solution", '
            'value:"No solution was made available by the vendor.\n\n  Note: '
            '<add a specific note for the reason here>.");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckSolutionText(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_ok3(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"solution_type", value:"WillNotFix");\n'
            '  script_tag(name:"solution", '
            'value:"No solution was made available by the vendor.\n\n  Vendor '
            'statement: <add specific vendor statement here>.");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckSolutionText(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_nok(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = '  script_tag(name:"solution_type", value:"NoneAvailable");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckSolutionText(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "The VT with solution type 'NoneAvailable' is using an "
            "incorrect syntax in the solution text. Please use (EXACTLY):\n"
            '  script_tag(name:"solution", value:"No known solution is '
            "available as of dd(st|nd|rd|th) mmmmmmmm, yyyy.\n  Information "
            "regarding this issue will be updated once solution details "
            'are available.");',
            results[0].message,
        )

    def test_nok2(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = '  script_tag(name:"solution_type", value:"WillNotFix");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckSolutionText(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            CORRECT_WILLNOTFIX_SUGGESTION,
            results[0].message,
        )

    def test_nok3(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"solution_type", value:"WillNotFix");\n'
            '  script_tag(name:"solution", '
            'value:"No solution was made available by the vendor.\n\n  Notice: '
            '<add a specific note for the reason here>.");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckSolutionText(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            CORRECT_WILLNOTFIX_SUGGESTION,
            results[0].message,
        )

    def test_nok4(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"solution_type", value:"WillNotFix");\n'
            '  script_tag(name:"solution", '
            'value:"No solution was made available by the vendor.\n\n  Vendor '
            'statment: <add specific vendor statement here>.");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckSolutionText(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            CORRECT_WILLNOTFIX_SUGGESTION,
            results[0].message,
        )

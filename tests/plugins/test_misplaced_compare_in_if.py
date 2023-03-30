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
from troubadix.plugins.misplaced_compare_in_if import CheckMisplacedCompareInIf

from . import PluginTestCase


class CheckMisplacedCompareInIfTestCase(PluginTestCase):
    def test_ok(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_ok2(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            'if( "text" >< variable ) {}\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_ok3(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            'if( "text" >< variable )\nexit(1);\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_ok4(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            'if( "text" >!< variable ) {}\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_ok5(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            'if( "text" >!< variable )\nexit(1);\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_ok6(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            'else if( "text" >< variable ) {}\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_ok7(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            'else if( "text" >< variable )\nexit(1);\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_ok8(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            'else if( "text" >!< variable ) {}\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_ok9(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            'else if( "text" >!< variable )\nexit(1);\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_ok10(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            '} else if( "text" >< variable ) {}\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_ok11(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            '} else if( "text" >< variable )\nexit(1);\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_ok12(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            '} else if( "text" >!< variable ) {}\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_ok13(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            '} else if( "text" >!< variable )\nexit(1);\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_nok(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            'if( variable >< "text" ) {}\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT/Include is using a misplaced compare "
            "within an if() call in "
            'if( variable >< "text" ) {',
            results[0].message,
        )

    def test_nok2(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            'if( variable >< "text" )\nexit(1);\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT/Include is using a misplaced compare "
            "within an if() call in "
            'if( variable >< "text" )\nexit(1);',
            results[0].message,
        )

    def test_nok3(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            'if( variable >!< "text" ) {}\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT/Include is using a misplaced compare "
            "within an if() call in "
            'if( variable >!< "text" ) {',
            results[0].message,
        )

    def test_nok4(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            'if( variable >!< "text" )\nexit(1);\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT/Include is using a misplaced compare "
            "within an if() call in "
            'if( variable >!< "text" )\nexit(1);',
            results[0].message,
        )

    def test_nok5(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            'else if( variable >< "text" ) {}\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT/Include is using a misplaced compare "
            "within an if() call in "
            'else if( variable >< "text" ) {',
            results[0].message,
        )

    def test_nok6(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            'else if( variable >< "text" )\nexit(1);\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT/Include is using a misplaced compare "
            "within an if() call in "
            'else if( variable >< "text" )\nexit(1);',
            results[0].message,
        )

    def test_nok7(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            'else if( variable >!< "text" ) {}\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT/Include is using a misplaced compare "
            "within an if() call in "
            'else if( variable >!< "text" ) {',
            results[0].message,
        )

    def test_nok8(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            'else if( variable >!< "text" )\nexit(1);\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT/Include is using a misplaced compare "
            "within an if() call in "
            'else if( variable >!< "text" )\nexit(1);',
            results[0].message,
        )

    def test_nok9(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            '} else if( variable >< "text" ) {}\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT/Include is using a misplaced compare "
            "within an if() call in "
            '} else if( variable >< "text" ) {',
            results[0].message,
        )

    def test_nok10(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            '} else if( variable >< "text" )\nexit(1);\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT/Include is using a misplaced compare "
            "within an if() call in "
            '} else if( variable >< "text" )\nexit(1);',
            results[0].message,
        )

    def test_nok11(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            '} else if( variable >!< "text" ) {}\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT/Include is using a misplaced compare "
            "within an if() call in "
            '} else if( variable >!< "text" ) {',
            results[0].message,
        )

    def test_nok12(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            '} else if( variable >!< "text" )\nexit(1);\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckMisplacedCompareInIf(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT/Include is using a misplaced compare "
            "within an if() call in "
            '} else if( variable >!< "text" )\nexit(1);',
            results[0].message,
        )

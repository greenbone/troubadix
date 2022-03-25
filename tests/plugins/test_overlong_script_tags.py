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
from troubadix.plugins.overlong_script_tags import CheckOverlongScriptTags

from . import PluginTestCase


class CheckOverlongScriptTagsTestCase(PluginTestCase):
    def test_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"summary", value:"Shorter than 1000");\n'
            'script_tag(name:"impact", value:"Shorter than 1000");\n'
            'script_tag(name:"affected", value:"Shorter than 1000");\n'
            'script_tag(name:"insight", value:"Shorter than 1000");\n'
            'script_tag(name:"vuldetect", value:"Shorter than 1000");\n'
            'script_tag(name:"solution", value:"Shorter than 1000");\n'
        )
        results = list(
            CheckOverlongScriptTags.run(
                path,
                content.splitlines(),
            )
        )
        self.assertEqual(len(results), 0)

    def test_no_nasl_file(self):
        path = Path("some/file.inc")
        content = 'script_tag(name:"summary", value:"Shorter than 1000");\n'
        results = list(
            CheckOverlongScriptTags.run(
                path,
                content.splitlines(),
            )
        )
        self.assertEqual(len(results), 0)

    def test_ignore_file(self):
        path = Path("monstra_cms_mult_vuln")
        content = (
            'script_tag(name:"summary", value:"Shorter than 1000");\n'
            'script_tag(name:"impact", value:"Shorter than 1000");\n'
            'script_tag(name:"affected", value:"Shorter than 1000");\n'
            'script_tag(name:"insight", value:"Shorter than 1000");\n'
            'script_tag(name:"vuldetect", value:"Shorter than 1000");\n'
        )
        results = list(
            CheckOverlongScriptTags.run(
                path,
                content.splitlines(),
            )
        )
        self.assertEqual(len(results), 0)

    def test_one_wrong_entry(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"summary", value:"Shorter than 1000");\n'
            'script_tag(name:"impact", value:"Shorter than 1000");\n'
            'script_tag(name:"affected", value:"Shorter than 1000");\n'
            'script_tag(name:"insight", value:"Shorter than 1000");\n'
            'script_tag(name:"vuldetect", value:"Shorter than 1000");\n'
            'script_tag(name:"solution", value:"Loooooooooooooooooooooooooooooo'
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            'oooooooooooooooooooooooooooooooooooooooooooooooonger");\n'
        )
        results = list(
            CheckOverlongScriptTags.run(
                path,
                content.splitlines(),
            )
        )
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            results[0].message,
            "line     6: contains overlong solution with 1007 characters",
        )

    def test_multiple_wrong_entries(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"summary", value:"Loooooooooooooooooooooooooooooo'
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            'oooooooooooooooooooooooooooooooooooooooooooooooonger");\n'
            'script_tag(name:"impact", value:"Shorter than 1000");\n'
            'script_tag(name:"affected", value:"Shorter than 1000");\n'
            'script_tag(name:"insight", value:"Shorter than 1000");\n'
            'script_tag(name:"vuldetect", value:"Shorter than 1000");\n'
            'script_tag(name:"solution", value:"Loooooooooooooooooooooooooooooo'
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            'oooooooooooooooooooooooooooooooooooooooooooooooonger");\n'
        )
        results = list(
            CheckOverlongScriptTags.run(
                path,
                content.splitlines(),
            )
        )
        self.assertEqual(len(results), 2)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            results[0].message,
            "line     1: contains overlong summary with 1007 characters",
        )

        self.assertIsInstance(results[1], LinterError)
        self.assertEqual(
            results[1].message,
            "line     6: contains overlong solution with 1007 characters",
        )

    def test_all_wrong_entries(self):
        path = Path("some/files.nasl")
        content = (
            'script_tag(name:"summary", value:"Loooooooooooooooooooooooooooooo'
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            'oooooooooooooooooooooooooooooooooooooooooooooooonger");\n'
            'script_tag(name:"impact", value:"Loooooooooooooooooooooooooooooo'
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            'oooooooooooooooooooooooooooooooooooooooooooooooonger");\n'
            'script_tag(name:"affected", value:"Loooooooooooooooooooooooooooooo'
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            'oooooooooooooooooooooooooooooooooooooooooooooooonger");\n'
            'script_tag(name:"insight", value:"Loooooooooooooooooooooooooooooo'
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            'oooooooooooooooooooooooooooooooooooooooooooooooonger");\n'
            'script_tag(name:"vuldetect", value:"Looooooooooooooooooooooooooooo'
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            'ooooooooooooooooooooooooooooooooooooooooooooo0ooonger");\n'
            'script_tag(name:"solution", value:"Loooooooooooooooooooooooooooooo'
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            'oooooooooooooooooooooooooooooooooooooooooooooooonger");\n'
        )
        results = list(
            CheckOverlongScriptTags.run(
                path,
                content.splitlines(),
            )
        )
        self.assertEqual(len(results), 6)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            results[0].message,
            "line     1: contains overlong summary with 1007 characters",
        )

        self.assertIsInstance(results[1], LinterError)
        self.assertEqual(
            results[1].message,
            "line     2: contains overlong impact with 1007 characters",
        )

        self.assertIsInstance(results[2], LinterError)
        self.assertEqual(
            results[2].message,
            "line     3: contains overlong affected with 1007 characters",
        )

        self.assertIsInstance(results[3], LinterError)
        self.assertEqual(
            results[3].message,
            "line     4: contains overlong insight with 1007 characters",
        )

        self.assertIsInstance(results[4], LinterError)
        self.assertEqual(
            results[4].message,
            "line     5: contains overlong vuldetect with 1007 characters",
        )

        self.assertIsInstance(results[5], LinterError)
        self.assertEqual(
            results[5].message,
            "line     6: contains overlong solution with 1007 characters",
        )

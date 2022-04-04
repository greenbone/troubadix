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
from troubadix.plugins.description import CheckDescription
from . import PluginTestCase


class CheckDescriptionTestCase(PluginTestCase):
    def test_ok(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            'script_cve_id("CVE-2021-03807");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'script_cve_id("CVE-2019-04879");\n'
            'script_tag(name:"solution", value:"meh");\n'
        )

        results = list(
            CheckDescription.run(
                nasl_file,
                content,
            )
        )
        self.assertEqual(len(results), 0)

    def test_description(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            'script_cve_id("CVE-2021-03807");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'script_cve_id("CVE-2019-04879");\n'
            'script_tag(name:"solution", value:"meh");\n'
            'script_description("TestTest");\n'
        )

        results = list(
            CheckDescription.run(
                nasl_file,
                content,
            )
        )
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT/Include is using deprecated 'script_description'",
            results[0].message,
        )

    def test_description2(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            'script_cve_id("CVE-2021-03807");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'TTTTTTTscrIpt_descriPtion("TestTest");\n'
            'script_cve_id("CVE-2019-04879");\n'
            'script_tag(name:"solution", value:"meh");\n'
        )

        results = list(
            CheckDescription.run(
                nasl_file,
                content,
            )
        )
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT/Include is using deprecated 'script_description'",
            results[0].message,
        )

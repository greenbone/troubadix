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
from troubadix.plugins.http_links_in_tags import CheckHttpLinksInTags

from . import PluginTestCase


class CheckHttpLinksInTagsTestCase(PluginTestCase):
    def test_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
            'get_app_port_from_cpe_prefix("cpe:/o:foo:bar");\n'
        )

        results = list(
            CheckHttpLinksInTags.run(
                path,
                content,
            )
        )
        self.assertEqual(len(results), 0)

    def test_not_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar. '
            'https://www.website.de/demo");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
        )

        results = list(
            CheckHttpLinksInTags.run(
                path,
                content,
            )
        )
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "One script_tag in the VT is using a "
            "HTTP link/URL which should be moved to a separate "
            '\'script_xref(name:"URL", value:"");\' tag instead: '
            '\'script_tag(name:"summary", value:"Foo Bar. '
            "https://www.website.de/demo\");'",
            results[0].message,
        )

    def test_not_ok2(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
            'script_xref(name:"URL", '
            'value:"https://nvd.nist.gov/vuln/detail/CVE-1234");\n'
        )

        results = list(
            CheckHttpLinksInTags.run(
                path,
                content,
            )
        )
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "The following script_xref is pointing "
            "to Mitre/NVD which is already covered by the script_cve_id. "
            "This is a redundant info and the script_xref needs to be "
            'removed: script_xref(name:"URL", '
            'value:"https://nvd.nist.gov/vuln/detail/CVE-1234");',
            results[0].message,
        )

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
from troubadix.plugins.reporting_consistency import CheckReportingConsistency
from tests.plugins import PluginTestCase


class CheckReportingConsistencyTestCase(PluginTestCase):
    def test_ok(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            'script_tag(name:"cvss_base", value:"0.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
            "log_message('Test');\n"
        )

        results = list(
            CheckReportingConsistency.run(
                nasl_file=nasl_file,
                file_content=content,
                tag_pattern=self.tag_pattern,
                special_tag_pattern=self.special_tag_pattern,
            )
        )
        self.assertEqual(len(results), 0)

    def test_ok2(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
            "security_message( port:port, data:'It was possible to get the "
            "csrf token `' + token[1] + '` via a jsonp request to: ' + "
            "http_report_vuln_url( port:port, url:url, url_only:TRUE ) );\n"
        )

        results = list(
            CheckReportingConsistency.run(
                nasl_file=nasl_file,
                file_content=content,
                tag_pattern=self.tag_pattern,
                special_tag_pattern=self.special_tag_pattern,
            )
        )
        self.assertEqual(len(results), 0)

    def test_fail(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            'script_tag(name:"cvss_base", value:"0.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
            "security_message( port:port, data:'It was possible to get the "
            "csrf token `' + token[1] + '` via a jsonp request to: ' + "
            "http_report_vuln_url( port:port, url:url, url_only:TRUE ) );\n"
        )

        results = list(
            CheckReportingConsistency.run(
                nasl_file=nasl_file,
                file_content=content,
                tag_pattern=self.tag_pattern,
                special_tag_pattern=self.special_tag_pattern,
            )
        )
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "Tag cvss_base is 0.0 use report function log_message",
            results[0].message,
        )

    def test_fail2(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
            "security_message( port:port, data:'It was possible to get the "
            "csrf token `' + token[1] + '` via a jsonp request to: ' + "
            "http_report_vuln_url( port:port, url:url, url_only:TRUE ) );\n"
        )

        results = list(
            CheckReportingConsistency.run(
                nasl_file=nasl_file,
                file_content=content,
                tag_pattern=self.tag_pattern,
                special_tag_pattern=self.special_tag_pattern,
            )
        )
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT/Include has no cvss_base tag",
            results[0].message,
        )

    def test_fail3(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            'script_tag(name:"cvss_base", value:"5.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
            "log_message( port:port, data:'It was possible to get the "
            "csrf token `' + token[1] + '` via a jsonp request to: ' + "
            "http_report_vuln_url( port:port, url:url, url_only:TRUE ) );\n"
        )

        results = list(
            CheckReportingConsistency.run(
                nasl_file=nasl_file,
                file_content=content,
                tag_pattern=self.tag_pattern,
                special_tag_pattern=self.special_tag_pattern,
            )
        )
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "Tag cvss_base is not 0.0 use report function security_message",
            results[0].message,
        )
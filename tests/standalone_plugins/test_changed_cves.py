# Copyright (C) 2023 Greenbone AG
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

from unittest import TestCase
from unittest.mock import patch

from troubadix.standalone_plugins.changed_cves import (
    compare,
    get_cves_from_content,
)


class ChangedCVEsTest(TestCase):
    def test_get_cves_from_content(self):
        content = (
            "...\n"
            '  script_oid("1.3.6.1.4.1.25623.1.0.705311");\n'
            '  script_version("2023-01-10T10:12:01+0000");\n'
            '  script_cve_id("CVE-2022-32749", "CVE-2022-37392");\n'
            '  script_tag(name:"cvss_base", value:"5.0");\n'
            "..."
        )

        expected_result = {"CVE-2022-32749", "CVE-2022-37392"}

        result = get_cves_from_content(content)

        self.assertEqual(expected_result, result)

    def test_get_cves_from_content_multiline(self):
        content = (
            "...\n"
            '  script_oid("1.3.6.1.4.1.25623.1.0.705311");\n'
            '  script_version("2023-01-10T10:12:01+0000");\n'
            '  script_cve_id("CVE-2022-32749",\n'
            '"CVE-2022-37392");\n'
            '  script_tag(name:"cvss_base", value:"5.0");\n'
            "..."
        )

        expected_result = {"CVE-2022-32749", "CVE-2022-37392"}

        result = get_cves_from_content(content)

        self.assertEqual(expected_result, result)

    def test_get_cves_from_content_empty(self):
        content = (
            "...\n"
            '  script_oid("1.3.6.1.4.1.25623.1.0.705311");\n'
            '  script_version("2023-01-10T10:12:01+0000");\n'
            '  script_tag(name:"cvss_base", value:"5.0");\n'
            "..."
        )

        expected_result = set()

        result = get_cves_from_content(content)

        self.assertEqual(expected_result, result)

    @patch("troubadix.standalone_plugins.changed_cves.get_cves_from_content")
    def test_compare(self, mock):
        mock.side_effect = [
            {"CVE-3333-3333", "CVE-2222-2222", "CVE-1111-1111"},
            {"CVE-1111-1111", "CVE-4444-4444"},
        ]

        expected_missing_cves = ["CVE-2222-2222", "CVE-3333-3333"]
        expected_new_cves = ["CVE-4444-4444"]

        missing_cves, new_cves = compare("", "")

        self.assertEqual(expected_missing_cves, missing_cves)
        self.assertEqual(expected_new_cves, new_cves)

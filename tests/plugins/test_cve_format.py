# Copyright (C) 2021 Greenbone Networks GmbH
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

from datetime import datetime
from pathlib import Path

from troubadix.plugin import LinterError, LinterWarning
from troubadix.plugins.cve_format import CheckCVEFormat

from . import PluginTestCase


class CheckCVEFormatTestCase(PluginTestCase):
    def test_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"7.5");\n'
            'script_cve_id("CVE-2022-23807");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckCVEFormat(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_exclude_inc_file(self):
        path = Path("some/file.inc")
        fake_context = self.create_file_plugin_context(nasl_file=path)
        plugin = CheckCVEFormat(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_detection_script(self):
        path = Path("some/file.nasl")
        content = 'script_tag(name:"cvss_base", value:"0.0");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckCVEFormat(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_no_cve_reference(self):
        path = Path("some/file.nasl")
        content = 'script_tag(name:"cvss_base", value:"7.5");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckCVEFormat(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterWarning)
        self.assertEqual(
            "VT does not refer to any CVEs.",
            results[0].message,
        )

    def test_invalid_cve_format(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"10.0");\n'
            'script_cve_id("CVE-a123-23807");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckCVEFormat(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT uses an invalid CVE format.",
            results[0].message,
        )

    def test_more_then_four_digits(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"7.5");\n'
            'script_cve_id("CVE-2021-03807");'
        )

        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckCVEFormat(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "The last group of CVE digits of the VT must not "
            "start with a 0 if there are more than 4 digits.",
            results[0].message,
        )

    def test_invalid_year(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"7.5");\n'
            'script_cve_id("CVE-1971-3807");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckCVEFormat(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT uses an invalid year in CVE format.",
            results[0].message,
        )

        current_year = datetime.now().year
        content = (
            'script_tag(name:"cvss_base", value:"7.5");\n'
            f'script_cve_id("CVE-{current_year + 1}-3807");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckCVEFormat(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT uses an invalid year in CVE format.",
            results[0].message,
        )

    def test_duplicate_cves(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"7.5");\n'
            'script_cve_id("CVE-2021-3807","CVE-2021-3807");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckCVEFormat(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            'VT is using CVE "CVE-2021-3807" multiple ' "times.",
            results[0].message,
        )

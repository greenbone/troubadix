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
from troubadix.plugins.cvss_format import CheckCVSSFormat

from . import PluginTestCase


class CheckCVSSFormatTestCase(PluginTestCase):
    def test_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"cvss_base_vector", '
            'value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");'
        )

        results = list(
            CheckCVSSFormat.run(
                path,
                content,
            )
        )
        self.assertEqual(len(results), 0)

    def test_invalid_base(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"a12");\n'
            'script_tag(name:"cvss_base_vector", '
            'value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");\n'
        )

        results = list(
            CheckCVSSFormat.run(
                path,
                content,
            )
        )
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT has a missing or invalid cvss_base value.",
            results[0].message,
        )

    def test_missing_base(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base_vector", '
            'value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");'
        )

        results = list(
            CheckCVSSFormat.run(
                path,
                content,
            )
        )
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT has a missing or invalid cvss_base value.",
            results[0].message,
        )

    def test_invalid_vector(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"cvss_base_vector", '
            'value:"AV:N/AC:L/Au:S/C:N/I:P/A:");'
        )

        results = list(
            CheckCVSSFormat.run(
                path,
                content,
            )
        )
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT has a missing or invalid cvss_base_vector value.",
            results[0].message,
        )

    def test_missing_vector(self):
        path = Path("some/file.nasl")
        content = 'script_tag(name:"cvss_base", value:"4.0");\n'

        results = list(
            CheckCVSSFormat.run(
                path,
                content,
            )
        )
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT has a missing or invalid cvss_base_vector value.",
            results[0].message,
        )

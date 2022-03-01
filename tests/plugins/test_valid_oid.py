# Copyright (c) 2022 Greenbone Networks GmbH
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

import unittest

from naslinter.plugin import LinterError, LinterMessage
from naslinter.plugins.valid_oid import CheckValidOID


class CheckValidOIDTestCase(unittest.TestCase):
    def test_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.0.122709");\n'
            'script_family("Oracle Linux Local Security Checks");\n'
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"cvss_base_vector", '
            'value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");'
        )

        results = list(CheckValidOID.run(path, content))
        print(results)
        self.assertEqual(len(results), 0)

    def test_nok(self):
        path = Path("file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"cvss_base_vector", '
            'value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterMessage)
        self.assertEqual(
            "No valid script_oid() call found.",
            results[0].message,
        )

    def test_invalid_oid(self):
        path = Path("file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.7.654321");\n'
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_name("Foo Bar");\n'
            'script_name("Foo Bar");\n'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "script_oid() is using an invalid OID "
            "'1.3.6.1.4.1.25623.1.7.654321' (last digits)",
            results[0].message,
        )

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
from unittest.mock import MagicMock

from troubadix.plugin import LinterError
from troubadix.plugins.duplicate_oid import CheckDuplicateOID

from . import PluginTestCase

here = Path(__file__).parent


class CheckDuplicateOIDTestCase(PluginTestCase):
    def test_ok(self):
        file1 = here / "test_files" / "nasl" / "21.04" / "fail.nasl"
        file2 = (
            here / "test_files" / "nasl" / "21.04" / "fail_name_newline.nasl"
        )
        context = MagicMock()
        context.nasl_files = [file1, file2]
        context.root = here
        plugin = CheckDuplicateOID(context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_ok_no_script_oid(self):
        file1 = (
            here / "test_files" / "nasl" / "21.04" / "fail_name_newline.nasl"
        )
        file2 = here / "test_files" / "nasl" / "21.04" / "fail_badwords.nasl"
        context = MagicMock()
        context.nasl_files = [file1, file2]
        context.root = here
        plugin = CheckDuplicateOID(context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "Could not find an OID"
            " in 'test_files/nasl/21.04/fail_badwords.nasl'.",
            results[0].message,
        )

    def test_duplicated_oid_function(self):
        file1 = here / "test_files" / "nasl" / "21.04" / "fail.nasl"
        file2 = here / "test_files" / "nasl" / "21.04" / "test.nasl"
        context = MagicMock()
        context.nasl_files = [file1, file2]
        context.root = here
        plugin = CheckDuplicateOID(context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "OID 1.3.6.1.4.1.25623.1.0.100312 already used by "
            "'test_files/nasl/21.04/fail.nasl'",
            results[0].message,
        )

    def test_invalid_oid(self):
        file2 = (
            here
            / "test_files"
            / "nasl"
            / "21.04"
            / "fail_name_and_copyright_newline.nasl"
        )
        context = MagicMock()
        context.nasl_files = [file2]
        context.root = here
        plugin = CheckDuplicateOID(context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "Invalid OID 1.2.3.4.5.6.78909.8.7.654321 found"
            " in 'test_files/nasl/21.04/fail_name_and_copyright_newline.nasl'.",
            results[0].message,
        )

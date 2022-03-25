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

from troubadix.plugin import LinterError, LinterMessage
from troubadix.plugins.duplicate_oid import CheckDuplicateOID

from . import PluginTestCase


class CheckDuplicateOIDTestCase(PluginTestCase):
    def test_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.2.3.4.5.6.78909.8.7.000000");\n'
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"cvss_base_vector", '
            'value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");'
        )

        results = list(
            CheckDuplicateOID.run(
                path,
                content,
            )
        )
        self.assertEqual(len(results), 0)

    def test_ok_no_script_oid(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"cvss_base_vector", '
            'value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");'
        )

        results = list(
            CheckDuplicateOID.run(
                path,
                content,
            )
        )
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterMessage)
        self.assertEqual(
            f"No OID found in VT '{str(path)}'",
            results[0].message,
        )

    def test_duplicated_oid_function(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.2.3.4.5.6.78909.8.7.654321");\n'
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_name("Foo Bar");\n'
            'script_name("Foo Bar");\n'
        )

        results = list(
            CheckDuplicateOID.run(
                path,
                content,
            )
        )
        self.assertEqual(len(results), 4)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "The OID '1.2.3.4.5.6.78909.8.7.654321' is also used in "
            "./tests/plugins/fail2.nasl:  "
            'script_oid("1.2.3.4.5.6.78909.8.7.654321");',
            results[0].message,
        )
        self.assertEqual(
            "The OID '1.2.3.4.5.6.78909.8.7.654321' is also used in "
            "./tests/plugins/test_files/fail_name_newline.nasl:  "
            'script_oid("1.2.3.4.5.6.78909.8.7.654321");',
            results[3].message,
        )

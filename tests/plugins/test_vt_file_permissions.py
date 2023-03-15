# Copyright (C) 2022 Greenbone AG
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
from troubadix.plugins.vt_file_permissions import CheckVTFilePermissions

from . import PluginTestCase


class CheckVTFilePermissionsTestCase(PluginTestCase):
    def test_ok(self):
        fake_context = self.create_file_plugin_context(
            nasl_file=Path(__file__).parent
            / "test_files"
            / "ok_permissions.nasl"
        )

        plugin = CheckVTFilePermissions(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_nok(self):
        fake_context = self.create_file_plugin_context(
            nasl_file=Path(__file__).parent
            / "test_files"
            / "fail_permissions.nasl"
        )

        plugin = CheckVTFilePermissions(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            results[0].message,
            "VT has invalid file permissions: -rwxr-xr-x.\n"
            "NASL scripts must not be executable.\n"
            "Typical file permissions are '644' (-rw-r--r-) "
            "and `664` (-rw-rw-r-)",
        )

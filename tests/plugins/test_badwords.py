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

from pathlib import Path

from troubadix.helper import CURRENT_ENCODING
from troubadix.plugin import LinterError
from troubadix.plugins.badwords import CheckBadwords

from . import PluginTestCase

root = Path(__file__).parent / "test_files"


class TestBadwords(PluginTestCase):
    def test_files(self):
        nasl_file = root / "fail_badwords.nasl"
        context = self.create_file_plugin_context(
            nasl_file=nasl_file,
            lines=nasl_file.read_text(encoding=CURRENT_ENCODING).splitlines(),
        )
        plugin = CheckBadwords(context)

        results = list(plugin.run())

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "Badword in line     1: openvas is a bad word",
            results[0].message,
        )
        self.assertEqual(
            "Badword in line    10: OpenVAS is a scanner",
            results[1].message,
        )

    def test_combined(self):
        path = Path("some/find_service3.nasl")
        content = "OpenVAS-8 and probably prior\nOpenVAS-9"

        fake_context = self.create_file_plugin_context(
            nasl_file=path, lines=content.splitlines()
        )

        plugin = CheckBadwords(fake_context)
        results = list(plugin.run())

        self.assertEqual(len(results), 0)

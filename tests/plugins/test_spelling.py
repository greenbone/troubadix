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
from unittest.mock import MagicMock

from troubadix.plugin import LinterWarning
from troubadix.plugins.spelling import CheckSpelling

from . import PluginTestCase


class CheckSpellingTestCase(PluginTestCase):
    def test_ok(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = "# this is not used, it use the nasl_file instead\n"
        fake_context = MagicMock()
        fake_context.nasl_file = nasl_file
        fake_context.file_content = content
        plugin = CheckSpelling(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_nok(self):
        nasl_file = Path(__file__).parent / "test_files" / "fail_spelling.nasl"
        content = "# this is not used, it use the nasl_file instead\n"
        fake_context = MagicMock()
        fake_context.nasl_file = nasl_file
        fake_context.file_content = content
        plugin = CheckSpelling(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterWarning)
        self.assertEqual(
            f"{nasl_file}:1: soltuion ==> solution\n"
            f"{nasl_file}:1: aviaalable ==> available\n"
            f"{nasl_file}:2: upated ==> updated\n",
            results[0].message,
        )

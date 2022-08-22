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
from troubadix.plugins.spelling import CheckSpelling

from . import PluginTestCase


class CheckSpellingTestCase(PluginTestCase):
    def test_ok(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        fake_context = self.create_files_plugin_context(nasl_files=[nasl_file])
        plugin = CheckSpelling(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_nok(self):
        nasl_file = Path(__file__).parent / "test_files" / "fail_spelling.nasl"
        fake_context = self.create_files_plugin_context(nasl_files=[nasl_file])
        plugin = CheckSpelling(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 3)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            f"{nasl_file}:1: soltuion ==> solution",
            results[0].message,
        )

        self.assertIsInstance(results[1], LinterError)
        self.assertEqual(
            f"{nasl_file}:1: aviaalable ==> available",
            results[1].message,
        )

        self.assertIsInstance(results[2], LinterError)
        self.assertEqual(
            f"{nasl_file}:2: upated ==> updated",
            results[2].message,
        )

    def test_local_files_nok(self):
        codespell_additions = Path("codespell.additions")
        codespell_additions.write_text("", encoding="utf-8")

        nasl_file = Path(__file__).parent / "test_files" / "fail_spelling.nasl"
        fake_context = self.create_files_plugin_context(nasl_files=[nasl_file])
        plugin = CheckSpelling(fake_context)

        results = list(plugin.run())

        codespell_additions.unlink()

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            f"{nasl_file}:1: soltuion ==> solution",
            results[0].message,
        )
        self.assertEqual(
            f"{nasl_file}:2: upated ==> updated",
            results[1].message,
        )

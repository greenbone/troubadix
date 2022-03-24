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
from troubadix.plugins.openvas_lint import CheckOpenvasLint

from . import PluginTestCase


class CheckOpenvasLintTestCase(PluginTestCase):
    def test_ok(self):
        nasl_file = (
            Path(__file__).parent
            / "test_files"
            / "nasl"
            / "21.04"
            / "test.nasl"
        )
        content = (
            "# this file content is not used - nasl_file is used instead\n"
        )

        results = list(
            CheckOpenvasLint.run(
                nasl_file=nasl_file,
                file_content=content,
            )
        )
        self.assertEqual(len(results), 0)

    def test_nok(self):
        nasl_file = (
            Path(__file__).parent
            / "test_files"
            / "nasl"
            / "21.04"
            / "fail.nasl"
        )
        content = (
            "# this file content is not used - nasl_file is used instead\n"
        )

        results = list(
            CheckOpenvasLint.run(
                nasl_file=nasl_file,
                file_content=content,
            )
        )
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            f"Error while processing {str(nasl_file)}.\n1 errors found",
            results[0].message,
        )

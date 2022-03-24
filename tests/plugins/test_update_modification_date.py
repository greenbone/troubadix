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

from troubadix.plugin import LinterError, LinterResult
from troubadix.plugins.update_modification_date import UpdateModificationDate

from . import PluginTestCase


class TestUpdateModificationDate(PluginTestCase):
    def test_change_date(self):
        nasl_file = Path(__file__).parent / "test.nasl"

        content = nasl_file.read_text(encoding="latin1")

        output = UpdateModificationDate.run(
            nasl_file=nasl_file,
            file_content=content,
        )

        self.assertIsInstance(next(output), LinterResult)

        new_content = nasl_file.read_text(encoding="latin1")
        self.assertNotEqual(content, new_content)

        # revert changes for the next time
        nasl_file.write_text(content, encoding="latin1")

    def test_fail_modification_date(self):
        nasl_file = Path(__file__).parent / "fail.nasl"

        content = nasl_file.read_text(encoding="latin1")

        output = UpdateModificationDate.run(
            nasl_file=nasl_file,
            file_content=content,
        )

        expected_error = LinterError(
            f"{nasl_file} does not contain a modification day script tag."
        )

        error = next(output)
        self.assertIsInstance(error, LinterError)
        self.assertEqual(error, expected_error)

        new_content = nasl_file.read_text(encoding="latin1")
        self.assertEqual(content, new_content)

    def test_fail_script_version(self):
        nasl_file = Path(__file__).parent / "fail2.nasl"

        content = nasl_file.read_text(encoding="latin1")

        output = UpdateModificationDate.run(
            nasl_file=nasl_file,
            file_content=content,
        )

        expected_error = LinterError(
            f"{nasl_file} does not contain a script version."
        )

        error = next(output)
        self.assertIsInstance(error, LinterError)
        self.assertEqual(error, expected_error)

        new_content = nasl_file.read_text(encoding="latin1")
        self.assertEqual(content, new_content)

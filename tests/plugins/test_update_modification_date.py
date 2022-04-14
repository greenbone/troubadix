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
from unittest.mock import MagicMock

from troubadix.helper import CURRENT_ENCODING
from troubadix.plugin import LinterError, LinterResult
from troubadix.plugins.update_modification_date import UpdateModificationDate

from . import PluginTestCase


class TestUpdateModificationDate(PluginTestCase):
    def test_change_date(self):
        nasl_file = Path(__file__).parent / "test.nasl"

        content = nasl_file.read_text(encoding=CURRENT_ENCODING)
        fake_context = MagicMock()
        fake_context.nasl_file = nasl_file
        fake_context.file_content = content
        plugin = UpdateModificationDate(fake_context)

        output = plugin.run()

        self.assertIsInstance(next(output), LinterResult)

        new_content = nasl_file.read_text(encoding=CURRENT_ENCODING)
        self.assertNotEqual(content, new_content)

        # revert changes for the next time
        nasl_file.write_text(content, encoding=CURRENT_ENCODING)

    def test_fail_modification_date(self):
        nasl_file = Path(__file__).parent / "fail.nasl"

        content = nasl_file.read_text(encoding=CURRENT_ENCODING)
        fake_context = MagicMock()
        fake_context.nasl_file = nasl_file
        fake_context.file_content = content
        plugin = UpdateModificationDate(fake_context)

        output = plugin.run()

        expected_error = LinterError(
            "VT does not contain a modification day script tag."
        )

        error = next(output)
        self.assertIsInstance(error, LinterError)
        self.assertEqual(error, expected_error)

        new_content = nasl_file.read_text(encoding=CURRENT_ENCODING)
        self.assertEqual(content, new_content)

    def test_fail_script_version(self):
        nasl_file = Path(__file__).parent / "fail2.nasl"

        content = nasl_file.read_text(encoding=CURRENT_ENCODING)

        fake_context = MagicMock()
        fake_context.nasl_file = nasl_file
        fake_context.file_content = content
        plugin = UpdateModificationDate(fake_context)

        output = plugin.run()

        expected_error = LinterError("VT does not contain a script version.")

        error = next(output)
        self.assertIsInstance(error, LinterError)
        self.assertEqual(error, expected_error)

        new_content = nasl_file.read_text(encoding=CURRENT_ENCODING)
        self.assertEqual(content, new_content)

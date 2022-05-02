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

from troubadix.helper import CURRENT_ENCODING
from troubadix.plugin import LinterError, LinterFix, LinterWarning
from troubadix.plugins.update_modification_date import UpdateModificationDate

from . import PluginTestCase


class TestUpdateModificationDate(PluginTestCase):
    def test_fix_last_modifaction_date(self):
        nasl_file = Path(__file__).parent / "test.nasl"

        content = nasl_file.read_text(encoding=CURRENT_ENCODING)
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = UpdateModificationDate(fake_context)

        results = list(plugin.run())

        self.assertIsInstance(results[0], LinterWarning)

        results = list(plugin.fix())

        self.assertIsInstance(results[0], LinterFix)

        new_content = nasl_file.read_text(encoding=CURRENT_ENCODING)
        self.assertNotEqual(content, new_content)

        # revert changes for the next time
        nasl_file.write_text(content, encoding=CURRENT_ENCODING)

    def test_fail_modification_date(self):
        nasl_file = Path(__file__).parent / "fail.nasl"

        content = nasl_file.read_text(encoding=CURRENT_ENCODING)
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = UpdateModificationDate(fake_context)

        output = plugin.run()

        error = next(output)
        self.assertIsInstance(error, LinterError)
        self.assertEqual(
            error.message, "VT does not contain a modification day script tag."
        )

        new_content = nasl_file.read_text(encoding=CURRENT_ENCODING)
        self.assertEqual(content, new_content)

    def test_fail_script_version(self):
        nasl_file = Path(__file__).parent / "fail2.nasl"

        content = nasl_file.read_text(encoding=CURRENT_ENCODING)

        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = UpdateModificationDate(fake_context)

        output = plugin.run()
        error = next(output)

        self.assertIsInstance(error, LinterError)
        self.assertEqual(error.message, "VT does not contain a script version.")

        new_content = nasl_file.read_text(encoding=CURRENT_ENCODING)
        self.assertEqual(content, new_content)

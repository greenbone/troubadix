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
from troubadix.plugin import LinterFix
from troubadix.plugins.last_modification import CheckLastModification

from . import PluginTestCase


class TestUpdateModificationDate(PluginTestCase):
    def test_fix_last_modifaction_date(self):
        with self.create_directory() as testdir:
            nasl_file = testdir / "test.nasl"
            content = (
                'script_tag(name:"last_modification", '
                'value:"2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)");\n'
                'script_version("2021-03-24T10:08:26+0000");\n'
            )
            nasl_file.write_text(content, encoding=CURRENT_ENCODING)
            fake_context = self.create_file_plugin_context(
                nasl_file=nasl_file, file_content=content
            )
            plugin = CheckLastModification(fake_context)

            results = list(plugin.run())

            self.assertEqual(len(results), 0)

            results = list(plugin.fix())

            self.assertEqual(len(results), 1)
            self.assertIsInstance(results[0], LinterFix)

            new_content = nasl_file.read_text(encoding=CURRENT_ENCODING)
            self.assertNotEqual(content, new_content)

    def test_ignore(self):
        nasl_file = Path(__file__).parent / "fail.nasl"

        content = nasl_file.read_text(encoding=CURRENT_ENCODING)
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckLastModification(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 0)

        results = list(plugin.fix())
        self.assertEqual(len(results), 0)

        new_content = nasl_file.read_text(encoding=CURRENT_ENCODING)
        self.assertEqual(content, new_content)

    def test_ignore_missing_script_version(self):
        nasl_file = Path(__file__).parent / "fail2.nasl"

        content = nasl_file.read_text(encoding=CURRENT_ENCODING)

        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckLastModification(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 0)

        results = list(plugin.fix())
        self.assertEqual(len(results), 0)

        new_content = nasl_file.read_text(encoding=CURRENT_ENCODING)
        self.assertEqual(content, new_content)

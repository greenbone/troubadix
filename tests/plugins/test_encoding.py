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

from troubadix.helper import CURRENT_ENCODING
from troubadix.plugin import LinterError
from troubadix.plugins.encoding import CheckEncoding

from . import PluginTestCase


class CheckEncodingTestCase(PluginTestCase):
    def test_ok(self):
        with self.create_directory() as tempdir:
            path = tempdir / "file.nasl"

            # It seems, that these are the only valid characters for this
            path.write_text(
                "!\"#$%&'()*+,-./0123456789:;<=>"
                "?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
                "abcdefghijklmnopqrstuvwxyz{|}~",
                encoding="utf-8",
            )
            content = path.read_text(encoding=CURRENT_ENCODING)
            fake_context = self.create_file_plugin_context(
                nasl_file=path, file_content=content, lines=content.splitlines()
            )
            plugin = CheckEncoding(fake_context)

            results = list(plugin.run())

            self.assertEqual(len(results), 0)

    def test_some_invalid_characters(self):
        with self.create_directory() as tempdir:
            path = tempdir / "file.nasl"

            path.write_text(
                "ȺȺȺȺʉʉʉʉϾϾϾϾ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄ"
                "ÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ",
                encoding="utf-8",
            )
            content = path.read_text(encoding=CURRENT_ENCODING)
            fake_context = self.create_file_plugin_context(
                nasl_file=path, file_content=content, lines=content.splitlines()
            )
            plugin = CheckEncoding(fake_context)

            results = list(plugin.run())

            self.assertEqual(len(results), 3)

            self.assertIsInstance(results[0], LinterError)
            self.assertEqual(
                "VT uses a wrong encoding. Detected encoding is utf-8.",
                results[0].message,
            )
            self.assertEqual(
                "Found invalid character",
                results[1].message,
            )
            self.assertEqual(
                "Found invalid character",
                results[2].message,
            )

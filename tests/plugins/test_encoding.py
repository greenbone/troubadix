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

    def test_ok_iso_8859_1(self):
        """Test that all valid ISO-8859-1 characters pass encoding validation.

        This covers the issue reported in JIRA VTOPS-281 where characters like 'ä' and '®'
        should be valid when files are properly encoded as ISO-8859-1.
        """
        with self.create_directory() as tempdir:
            path = tempdir / "file.nasl"

            # All valid ISO-8859-1 characters (0-255)
            # ASCII printable characters (32-126) + Latin-1 supplement (160-255)
            latin1_chars = "".join(
                [chr(i) for i in list(range(32, 127)) + list(range(160, 256))]
            )

            path.write_text(
                latin1_chars,
                encoding="iso-8859-1",
            )
            content = path.read_text(encoding=CURRENT_ENCODING)
            fake_context = self.create_file_plugin_context(
                nasl_file=path, file_content=content, lines=content.splitlines()
            )
            plugin = CheckEncoding(fake_context)

            results = list(plugin.run())

            self.assertEqual(len(results), 0)

    def test_specific_latin1_chars_utf8_encoding_fails(self):
        """Test that specific Latin-1 characters fail when saved as UTF-8.

        This specifically tests the JIRA VTOPS-281 reported issue where 'ä' and '®'
        cause encoding problems when saved as UTF-8 but read as ISO-8859-1.
        """
        with self.create_directory() as tempdir:
            path = tempdir / "file.nasl"

            # Specific characters that were problematic: ä (U+00E4) and ® (U+00AE)
            path.write_text(
                "This contains ä and ® characters",
                encoding="utf-8",
            )
            content = path.read_text(encoding=CURRENT_ENCODING)
            fake_context = self.create_file_plugin_context(
                nasl_file=path, file_content=content, lines=content.splitlines()
            )
            plugin = CheckEncoding(fake_context)

            results = list(plugin.run())

            self.assertEqual(len(results), 2)
            self.assertIsInstance(results[0], LinterError)
            self.assertEqual(
                "Detected encoding 'UTF-8' is not Latin-1 compatible.",
                results[0].message,
            )
            self.assertIsInstance(results[1], LinterError)
            self.assertEqual(
                "Likely UTF-8 multibyte sequence found in line 1",
                results[1].message,
            )

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

            self.assertEqual(len(results), 2)

            self.assertIsInstance(results[0], LinterError)
            self.assertEqual(
                "Detected encoding 'UTF-8' is not Latin-1 compatible.",
                results[0].message,
            )
            self.assertIsInstance(results[1], LinterError)
            self.assertEqual(
                "Likely UTF-8 multibyte sequence found in line 1",
                results[1].message,
            )

    def test_invisible_whitespace(self):
        with self.create_directory() as tempdir:
            path = tempdir / "file.nasl"

            # It seems, that these are the only valid characters for this
            path.write_text(
                "Local Privilege Escalation Vulnerability",
                encoding="utf-8",
            )
            content = path.read_text(encoding=CURRENT_ENCODING)
            fake_context = self.create_file_plugin_context(
                nasl_file=path, file_content=content, lines=content.splitlines()
            )
            plugin = CheckEncoding(fake_context)

            results = list(plugin.run())

            self.assertEqual(len(results), 2)
            self.assertIsInstance(results[0], LinterError)
            self.assertEqual(
                "Detected encoding 'UTF-8' is not Latin-1 compatible.",
                results[0].message,
            )
            self.assertIsInstance(results[1], LinterError)
            self.assertEqual(
                "Likely UTF-8 multibyte sequence found in line 1",
                results[1].message,
            )

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

import unittest
from unittest.mock import MagicMock

from tests.plugins import TemporaryDirectory
from troubadix.standalone_plugins.last_modification import parse_args, update


class ParseArgsTestCase(unittest.TestCase):
    def test_parse_files(self):
        with TemporaryDirectory() as tempdir:
            testfile1 = tempdir / "testfile1.nasl"
            testfile2 = tempdir / "testfile2.nasl"

            testfile1.touch()
            testfile2.touch()

            args = parse_args(["--file", str(testfile1), str(testfile2)])

            self.assertEqual(args.files[0], testfile1)
            self.assertEqual(args.files[1], testfile2)

    def test_parse_from_file(self):
        with TemporaryDirectory() as tempdir:
            from_file = tempdir / "from_file.txt"
            testfile1 = tempdir / "testfile1.nasl"
            testfile2 = tempdir / "testfile2.nasl"

            from_file.write_text(f"{testfile1}\n{testfile2}\n", encoding="utf8")

            args = parse_args(["--from-file", str(from_file)])

            self.assertEqual(args.from_file, from_file)


class UpdateTestCase(unittest.TestCase):
    def test_update(self):
        terminal = MagicMock()
        with TemporaryDirectory() as tempdir:
            content = (
                'script_version("2021-07-19T12:32:02+0000");\n'
                'script_tag(name: "last_modification", value: "2021-07-19 '
                '12:32:02 +0000 (Mon, 19 Jul 2021)");\n'
            )
            testfile1 = tempdir / "testfile1.nasl"
            testfile1.write_text(content, encoding="utf8")

            update(testfile1, terminal)

            new_content = testfile1.read_text(encoding="utf8")

            self.assertNotEqual(content, new_content)

    def test_update_invalid_date(self):
        terminal = MagicMock()
        with TemporaryDirectory() as tempdir:
            content = (
                'script_version("foo");\n'
                'script_tag(name: "last_modification", value: "bar");\n'
            )
            testfile1 = tempdir / "testfile1.nasl"
            testfile1.write_text(content, encoding="utf8")

            update(testfile1, terminal)

            new_content = testfile1.read_text(encoding="utf8")

            self.assertNotEqual(content, new_content)

    def test_no_update_missing_script_version(self):
        terminal = MagicMock()
        with TemporaryDirectory() as tempdir:
            content = 'script_tag(name: "last_modification", value: "bar");\n'
            testfile1 = tempdir / "testfile1.nasl"
            testfile1.write_text(content, encoding="utf8")

            update(testfile1, terminal)

            new_content = testfile1.read_text(encoding="utf8")

            self.assertEqual(content, new_content)

    def test_no_update_missing_last_modification_tag(self):
        terminal = MagicMock()
        with TemporaryDirectory() as tempdir:
            content = 'script_version("2021-07-19T12:32:02+0000");\n'
            testfile1 = tempdir / "testfile1.nasl"
            testfile1.write_text(content, encoding="utf8")

            update(testfile1, terminal)

            new_content = testfile1.read_text(encoding="utf8")

            self.assertEqual(content, new_content)

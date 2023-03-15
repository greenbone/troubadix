# Copyright (C) 2021 Greenbone AG
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
from pathlib import Path

from troubadix.helper import is_ignore_file
from troubadix.helper.helper import (
    get_path_from_root,
    get_root,
    is_enterprise_folder,
)


class IgnoreFile(unittest.TestCase):
    def test_compare_path_to_str(self):
        test_path = Path("foo/bar")

        self.assertTrue(is_ignore_file(test_path, ["foo"]))
        self.assertFalse(is_ignore_file(test_path, ["ipsum"]))

    def test_compare_path_to_path(self):
        test_path = Path("foo/bar")

        self.assertTrue(is_ignore_file(test_path, [Path("foo")]))
        self.assertFalse(is_ignore_file(test_path, [Path("ipsum")]))

    def test_compare_str_to_str(self):
        self.assertTrue(is_ignore_file("foo/bar", ["foo"]))
        self.assertFalse(is_ignore_file("foo/bar", ["ipsum"]))

    def test_compare_str_to_path(self):
        self.assertTrue(is_ignore_file("foo/bar", [Path("foo")]))
        self.assertFalse(is_ignore_file("foo/bar", [Path("ipsum")]))


class IsEnterpriseFolderTestCase(unittest.TestCase):
    def test_enterprise_folder(self):
        self.assertTrue(is_enterprise_folder(Path("enterprise")))
        self.assertTrue(is_enterprise_folder(Path("gsf")))
        self.assertTrue(is_enterprise_folder("enterprise"))
        self.assertTrue(is_enterprise_folder("gsf"))

        self.assertFalse(is_enterprise_folder("gcf"))
        self.assertFalse(is_enterprise_folder("foo"))
        self.assertFalse(is_enterprise_folder(Path("gcf")))
        self.assertFalse(is_enterprise_folder(Path("foo")))


class GetRootTestCase(unittest.TestCase):
    def test_get_root(self):
        self.assertEqual(get_root(Path("/nasl/foo/bar")), Path("/nasl"))
        self.assertEqual(get_root(Path("/nasl/common/bar")), Path("/nasl"))
        self.assertEqual(get_root(Path("/nasl/21.04/bar")), Path("/nasl"))
        self.assertEqual(get_root(Path("/nasl/22.04/bar")), Path("/nasl"))
        self.assertEqual(get_root(Path("/foo/bar")), Path("/"))
        self.assertEqual(get_root(Path("")), Path("/"))


class GetPathFromRootTestCase(unittest.TestCase):
    def test_get_path_from_root_relative(self):
        self.assertEqual(
            get_path_from_root(Path("nasl/foo"), Path("nasl/foo")), Path(".")
        )
        self.assertEqual(
            get_path_from_root(Path("nasl/foo"), Path("nasl")), Path("foo")
        )
        self.assertEqual(
            get_path_from_root(Path("nasl/foo/bar"), Path("nasl")),
            Path("foo/bar"),
        )

    def test_get_path_from_root_absolute(self):
        self.assertEqual(
            get_path_from_root(Path("/nasl/foo"), Path("/nasl/foo")), Path(".")
        )
        self.assertEqual(
            get_path_from_root(Path("/nasl/foo"), Path("/nasl")), Path("foo")
        )
        self.assertEqual(
            get_path_from_root(Path("/nasl/foo/bar"), Path("/nasl")),
            Path("foo/bar"),
        )

    # pylint: disable=expression-not-assigned
    def test_no_root_path(self):
        with self.assertRaises(ValueError):
            get_path_from_root(Path("nasl/foo/bar"), Path("nasl/baz/bar")),

        with self.assertRaises(ValueError):
            get_path_from_root(Path("/nasl/foo/bar"), Path("/nasl/baz/bar")),

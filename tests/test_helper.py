# Copyright (C) 2021 Greenbone Networks GmbH
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

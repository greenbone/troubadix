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

import os
from pathlib import Path
import unittest
import sys

from naslinter.naslinter import generate_file_list


class TestNASLinter(unittest.TestCase):
    def setUp(self):
        # store old arguments
        self.old_args = sys.argv

    def tearDown(self) -> None:
        # reset old arguments
        sys.argv = self.old_args

    def test_generate_file_list_with_exclude_regex(self):
        files = generate_file_list(
            dirs=[Path(os.getcwd())],
            excluded=["**/test.nasl", "**/templates/*/*.nasl"],
            dglobs=["**/*.nasl", "**/*.inc"],
        )
        print(files)

        self.assertEqual(
            files,
            [
                Path(
                    "/Users/jloechte/greenbone/"
                    "nasl-linter/tests/plugins/fail.nasl"
                ),
                Path(
                    "/Users/jloechte/greenbone/"
                    "nasl-linter/tests/plugins/fail2.nasl"
                ),
            ],
        )

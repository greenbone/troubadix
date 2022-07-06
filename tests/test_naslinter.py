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

import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

from pontos.terminal import Terminal

from troubadix.troubadix import generate_file_list, generate_patterns


class TestNASLinter(unittest.TestCase):
    def setUp(self):
        # store old arguments
        self.old_args = sys.argv

    def tearDown(self) -> None:
        # reset old arguments
        sys.argv = self.old_args

    def test_generate_file_list_with_exclude_patterns(self):
        cwd = Path.cwd()
        files = generate_file_list(
            dirs=[cwd],
            exclude_patterns=[
                "**/test.nasl",
                "**/*.inc",
                "**/templates/*/*.nasl",
                "**/test_files/*",
                "**/test_files/**/*.nasl",
            ],
            include_patterns=["**/*.nasl", "**/*.inc"],
        )
        expected_files = [
            Path(f"{cwd}/tests/plugins/fail.nasl"),
            Path(f"{cwd}/tests/plugins/fail2.nasl"),
        ]
        expected_files.sort()
        files.sort()

        self.assertEqual(files, expected_files)

    def test_generate_file_list_with_include_patterns(self):
        cwd = Path.cwd()
        files = generate_file_list(
            dirs=[cwd],
            exclude_patterns=None,
            include_patterns=["**/tests/*/*.nasl", "**/tests/*/*.inc"],
        )
        expected_files = [
            Path(f"{cwd}/tests/plugins/fail.nasl"),
            Path(f"{cwd}/tests/plugins/test.nasl"),
            Path(f"{cwd}/tests/plugins/fail2.nasl"),
        ]
        expected_files.sort()
        files.sort()

        self.assertEqual(files, expected_files)

    def test_generate_patterns_non_recursive(self):
        terminal = Mock(spec=Terminal)
        include_patterns = ["*.nasl", "*.inc"]
        exclude_patterns = ["test.nasl", "templates/*/*.nasl"]

        new_include_patterns, new_exclude_patterns = generate_patterns(
            terminal=terminal,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
            non_recursive=True,
        )

        self.assertEqual(new_include_patterns, include_patterns)
        self.assertEqual(new_exclude_patterns, exclude_patterns)

    def test_generate_patterns_recursive(self):
        terminal = Mock(spec=Terminal)
        include_patterns = ["*.nasl", "*.inc"]
        exclude_patterns = ["test.nasl", "templates/*/*.nasl"]

        new_include_patterns, new_exclude_patterns = generate_patterns(
            terminal=terminal,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
            non_recursive=False,
        )

        expected_include_patterns = ["**/*.nasl", "**/*.inc"]
        expected_exclude_patterns = ["**/test.nasl", "**/templates/*/*.nasl"]

        self.assertEqual(new_include_patterns, expected_include_patterns)
        self.assertEqual(new_exclude_patterns, expected_exclude_patterns)

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
from multiprocessing import cpu_count
from pathlib import Path
from unittest.mock import Mock

from pontos.terminal import _set_terminal

from troubadix.argparser import parse_args


class TestArgparsing(unittest.TestCase):
    def setUp(self):
        _set_terminal(Mock())

    def test_parse_files(self):
        parsed_args = parse_args(
            [
                "--files",
                "tests/plugins/test.nasl",
                "tests/plugins/fail2.nasl",
            ]
        )

        expected_files = [
            Path("tests/plugins/test.nasl"),
            Path("tests/plugins/fail2.nasl"),
        ]
        self.assertEqual(parsed_args.files, expected_files)

    def test_parse_include_tests(self):
        parsed_args = parse_args(
            [
                "--include-tests",
                "CheckBadwords",
            ]
        )
        self.assertEqual(parsed_args.included_plugins, ["CheckBadwords"])
        self.assertIsNone(parsed_args.excluded_plugins)
        self.assertFalse(parsed_args.update_date)

    def test_parse_exclude_tests(self):
        parsed_args = parse_args(
            [
                "--exclude-tests",
                "CheckBadwords",
            ]
        )
        self.assertEqual(parsed_args.excluded_plugins, ["CheckBadwords"])
        self.assertIsNone(parsed_args.included_plugins)
        self.assertFalse(parsed_args.update_date)

    def test_parse_include_patterns(self):
        parsed_args = parse_args(["-f", "--include-patterns", "troubadix/*"])

        self.assertTrue(parsed_args.full)
        self.assertEqual(parsed_args.include_patterns, ["troubadix/*"])

    def test_parse_include_patterns_fail(self):
        with self.assertRaises(SystemExit):
            parse_args(["--include-patterns", "troubadix/*"])

    def test_parse_files_non_recursive_fail(self):
        with self.assertRaises(SystemExit):
            parse_args(
                [
                    "--files",
                    "tests/plugins/test.nasl",
                    "tests/plugins/fail2.nasl",
                    "--non-recursive",
                ]
            )

    def test_parse_exclude_patterns(self):
        parsed_args = parse_args(["-f", "--exclude-patterns", "troubadix/*"])

        self.assertTrue(parsed_args.full)
        self.assertEqual(parsed_args.exclude_patterns, ["troubadix/*"])

    def test_parse_max_cpu(self):
        parsed_args = parse_args(
            [
                "-f",
                "--exclude-patterns",
                "troubadix/*",
                "-j",
                "1337",
            ]
        )

        self.assertTrue(parsed_args.full)
        self.assertEqual(parsed_args.exclude_patterns, ["troubadix/*"])

        self.assertEqual(parsed_args.n_jobs, cpu_count())

    def test_parse_min_cpu_update_date(self):
        parsed_args = parse_args(
            [
                "-f",
                "--exclude-patterns",
                "troubadix/*",
                "-j",
                "-1337",
                "--update-date",
            ]
        )

        self.assertTrue(parsed_args.full)
        self.assertEqual(parsed_args.exclude_patterns, ["troubadix/*"])

        self.assertEqual(parsed_args.n_jobs, cpu_count() // 2)

        self.assertTrue(parsed_args.update_date)

    def test_parse_root(self):
        parsed_args = parse_args(["--root", "foo"])

        self.assertEqual(parsed_args.root, Path("foo"))

    def test_parse_fix(self):
        parsed_args = parse_args(["--fix"])

        self.assertTrue(parsed_args.fix)

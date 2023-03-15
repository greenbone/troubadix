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
from multiprocessing import cpu_count
from pathlib import Path
from unittest.mock import Mock

from pontos.terminal import Terminal

from troubadix.argparser import parse_args


class TestArgparsing(unittest.TestCase):
    def setUp(self):
        self.terminal = Mock(spec=Terminal)

    def test_parse_files(self):
        parsed_args = parse_args(
            self.terminal,
            [
                "--files",
                "tests/plugins/test.nasl",
                "tests/plugins/fail2.nasl",
            ],
        )

        expected_files = [
            Path("tests/plugins/test.nasl"),
            Path("tests/plugins/fail2.nasl"),
        ]
        self.assertEqual(parsed_args.files, expected_files)

    def test_parse_include_tests(self):
        parsed_args = parse_args(
            self.terminal,
            [
                "--include-tests",
                "CheckBadwords",
            ],
        )
        self.assertEqual(parsed_args.included_plugins, ["CheckBadwords"])
        self.assertIsNone(parsed_args.excluded_plugins)

    def test_parse_exclude_tests(self):
        parsed_args = parse_args(
            self.terminal,
            [
                "--exclude-tests",
                "CheckBadwords",
            ],
        )
        self.assertEqual(parsed_args.excluded_plugins, ["CheckBadwords"])
        self.assertIsNone(parsed_args.included_plugins)

    def test_parse_include_patterns(self):
        parsed_args = parse_args(
            self.terminal, ["-f", "--include-patterns", "troubadix/*"]
        )

        self.assertTrue(parsed_args.full)
        self.assertEqual(parsed_args.include_patterns, ["troubadix/*"])

    def test_parse_include_patterns_fail(self):
        with self.assertRaises(SystemExit):
            parse_args(self.terminal, ["--include-patterns", "troubadix/*"])

    def test_parse_files_non_recursive_fail(self):
        with self.assertRaises(SystemExit):
            parse_args(
                self.terminal,
                [
                    "--files",
                    "tests/plugins/test.nasl",
                    "tests/plugins/fail2.nasl",
                    "--non-recursive",
                ],
            )

    def test_parse_exclude_patterns(self):
        parsed_args = parse_args(
            self.terminal, ["-f", "--exclude-patterns", "troubadix/*"]
        )

        self.assertTrue(parsed_args.full)
        self.assertEqual(parsed_args.exclude_patterns, ["troubadix/*"])

    def test_parse_max_cpu(self):
        parsed_args = parse_args(
            self.terminal,
            [
                "-f",
                "--exclude-patterns",
                "troubadix/*",
                "-j",
                "1337",
            ],
        )

        self.assertTrue(parsed_args.full)
        self.assertEqual(parsed_args.exclude_patterns, ["troubadix/*"])

        self.assertEqual(parsed_args.n_jobs, cpu_count())

    def test_parse_min_cpu(self):
        parsed_args = parse_args(
            self.terminal,
            [
                "-f",
                "--exclude-patterns",
                "troubadix/*",
                "-j",
                "-1337",
            ],
        )

        self.assertTrue(parsed_args.full)
        self.assertEqual(parsed_args.exclude_patterns, ["troubadix/*"])

        self.assertEqual(parsed_args.n_jobs, cpu_count() // 2)

    def test_parse_root(self):
        parsed_args = parse_args(self.terminal, ["--root", "foo"])

        self.assertEqual(parsed_args.root, Path("foo"))

    def test_parse_fix(self):
        parsed_args = parse_args(self.terminal, ["--fix"])

        self.assertTrue(parsed_args.fix)

    def test_parse_ignore_warnings(self):
        parsed_args = parse_args(self.terminal, ["--ignore-warnings"])

        self.assertTrue(parsed_args.ignore_warnings)

    def test_parse_log_file_statistic(self):
        parsed_args = parse_args(self.terminal, ["--log-file-statistic", "foo"])

        self.assertEqual(parsed_args.log_file_statistic, Path("foo"))

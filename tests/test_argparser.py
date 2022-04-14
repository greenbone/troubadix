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

from argparse import Namespace
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

        expected_args = Namespace(
            full=False,
            dirs=None,
            files=[
                Path("tests/plugins/test.nasl"),
                Path("tests/plugins/fail2.nasl"),
            ],
            from_file=None,
            no_statistic=False,
            verbose=0,
            log_file=None,
            non_recursive=False,
            include_patterns=None,
            exclude_patterns=None,
            excluded_plugins=None,
            included_plugins=None,
            n_jobs=cpu_count() // 2,
            update_date=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_include_tests(self):
        parsed_args = parse_args(
            [
                "--include-tests",
                "CheckBadwords",
            ]
        )

        expected_args = Namespace(
            full=False,
            dirs=None,
            files=None,
            from_file=None,
            no_statistic=False,
            verbose=0,
            log_file=None,
            non_recursive=False,
            include_patterns=None,
            exclude_patterns=None,
            excluded_plugins=None,
            included_plugins=["CheckBadwords"],
            n_jobs=cpu_count() // 2,
            update_date=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_exclude_tests(self):
        parsed_args = parse_args(
            [
                "--exclude-tests",
                "CheckBadwords",
            ]
        )

        expected_args = Namespace(
            full=False,
            dirs=None,
            files=None,
            from_file=None,
            no_statistic=False,
            verbose=0,
            log_file=None,
            non_recursive=False,
            include_patterns=None,
            exclude_patterns=None,
            excluded_plugins=["CheckBadwords"],
            included_plugins=None,
            n_jobs=cpu_count() // 2,
            update_date=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_include_patterns(self):
        parsed_args = parse_args(["-f", "--include-patterns", "troubadix/*"])

        expected_args = Namespace(
            full=True,
            dirs=None,
            files=None,
            from_file=None,
            no_statistic=False,
            verbose=0,
            log_file=None,
            non_recursive=False,
            include_patterns=["troubadix/*"],
            exclude_patterns=None,
            excluded_plugins=None,
            included_plugins=None,
            n_jobs=cpu_count() // 2,
            update_date=False,
        )

        self.assertEqual(parsed_args, expected_args)

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

        expected_args = Namespace(
            full=True,
            dirs=None,
            files=None,
            from_file=None,
            no_statistic=False,
            verbose=0,
            log_file=None,
            non_recursive=False,
            exclude_patterns=["troubadix/*"],
            include_patterns=None,
            excluded_plugins=None,
            included_plugins=None,
            n_jobs=cpu_count() // 2,
            update_date=False,
        )

        self.assertEqual(parsed_args, expected_args)

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

        expected_args = Namespace(
            full=True,
            dirs=None,
            files=None,
            from_file=None,
            no_statistic=False,
            verbose=0,
            log_file=None,
            non_recursive=False,
            exclude_patterns=["troubadix/*"],
            include_patterns=None,
            excluded_plugins=None,
            included_plugins=None,
            n_jobs=cpu_count(),
            update_date=False,
        )

        self.assertEqual(parsed_args, expected_args)

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

        expected_args = Namespace(
            full=True,
            dirs=None,
            files=None,
            from_file=None,
            no_statistic=False,
            verbose=0,
            log_file=None,
            non_recursive=False,
            exclude_patterns=["troubadix/*"],
            include_patterns=None,
            excluded_plugins=None,
            included_plugins=None,
            n_jobs=cpu_count() // 2,
            update_date=True,
        )

        self.assertEqual(parsed_args, expected_args)

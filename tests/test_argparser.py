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

import sys
import unittest
from argparse import Namespace
from multiprocessing import cpu_count
from pathlib import Path
from unittest.mock import Mock

from pontos.terminal import _set_terminal

from troubadix.argparser import parse_args


class TestArgparsing(unittest.TestCase):
    def setUp(self):
        # store old arguments
        self.old_args = sys.argv
        _set_terminal(Mock())

    def tearDown(self) -> None:
        # reset old arguments
        sys.argv = self.old_args

    def test_parse_full_verbose_staged(self):
        sys.argv = ["troubadix", "-f", "-vv", "--staged-only"]
        expcected_dirs = [Path.cwd()]

        parsed_args = parse_args()

        expected_args = Namespace(
            full=True,
            dirs=expcected_dirs,
            files=None,
            from_file=None,
            commit_range=None,
            staged_only=True,
            no_statistic=False,
            verbose=2,
            log_file=None,
            non_recursive=False,
            include_patterns=None,
            exclude_patterns=None,
            excluded_plugins=None,
            included_plugins=None,
            skip_duplicated_oids=False,
            n_jobs=cpu_count() // 2,
            update_date=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_files(self):
        sys.argv = [
            "troubadix",
            "--files",
            "tests/plugins/test.nasl",
            "tests/plugins/fail2.nasl",
        ]

        parsed_args = parse_args()

        expected_args = Namespace(
            full=False,
            dirs=None,
            files=[
                Path("tests/plugins/test.nasl"),
                Path("tests/plugins/fail2.nasl"),
            ],
            from_file=None,
            commit_range=None,
            staged_only=False,
            no_statistic=False,
            verbose=0,
            log_file=None,
            non_recursive=False,
            include_patterns=None,
            exclude_patterns=None,
            excluded_plugins=None,
            included_plugins=None,
            skip_duplicated_oids=False,
            n_jobs=cpu_count() // 2,
            update_date=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_dir_skip_duplicate(self):
        sys.argv = [
            "troubadix",
            "--dirs",
            "tests",
            "troubadix",
            "--skip-duplicated-oids",
            "--non-recursive",
        ]

        parsed_args = parse_args()

        expected_args = Namespace(
            full=False,
            dirs=[Path("tests"), Path("troubadix")],
            files=None,
            from_file=None,
            commit_range=None,
            staged_only=False,
            no_statistic=False,
            verbose=0,
            log_file=None,
            non_recursive=True,
            include_patterns=None,
            exclude_patterns=None,
            excluded_plugins=None,
            included_plugins=None,
            skip_duplicated_oids=True,
            n_jobs=cpu_count() // 2,
            update_date=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_commit_range(self):
        sys.argv = ["troubadix", "--commit-range", "0123456", "7abcdef"]

        parsed_args = parse_args()

        expected_args = Namespace(
            full=False,
            dirs=None,
            files=None,
            from_file=None,
            commit_range=["0123456", "7abcdef"],
            staged_only=False,
            no_statistic=False,
            verbose=0,
            log_file=None,
            non_recursive=False,
            include_patterns=None,
            exclude_patterns=None,
            excluded_plugins=None,
            included_plugins=None,
            skip_duplicated_oids=False,
            n_jobs=cpu_count() // 2,
            update_date=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_include_tests(self):
        sys.argv = [
            "troubadix",
            "--include-tests",
            "CheckBadwords",
        ]

        parsed_args = parse_args()

        expected_args = Namespace(
            full=False,
            dirs=None,
            files=None,
            from_file=None,
            commit_range=None,
            staged_only=False,
            no_statistic=False,
            verbose=0,
            log_file=None,
            non_recursive=False,
            include_patterns=None,
            exclude_patterns=None,
            excluded_plugins=None,
            included_plugins=["CheckBadwords"],
            skip_duplicated_oids=False,
            n_jobs=cpu_count() // 2,
            update_date=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_exclude_tests(self):
        sys.argv = [
            "troubadix",
            "--exclude-tests",
            "CheckBadwords",
        ]

        parsed_args = parse_args()

        expected_args = Namespace(
            full=False,
            dirs=None,
            files=None,
            from_file=None,
            commit_range=None,
            staged_only=False,
            no_statistic=False,
            verbose=0,
            log_file=None,
            non_recursive=False,
            include_patterns=None,
            exclude_patterns=None,
            excluded_plugins=["CheckBadwords"],
            included_plugins=None,
            skip_duplicated_oids=False,
            n_jobs=cpu_count() // 2,
            update_date=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_include_patterns(self):
        sys.argv = ["troubadix", "-f", "--include-patterns", "troubadix/*"]
        expcected_dirs = [Path.cwd()]

        parsed_args = parse_args()

        expected_args = Namespace(
            full=True,
            dirs=expcected_dirs,
            files=None,
            from_file=None,
            commit_range=None,
            staged_only=False,
            no_statistic=False,
            verbose=0,
            log_file=None,
            non_recursive=False,
            include_patterns=["troubadix/*"],
            exclude_patterns=None,
            excluded_plugins=None,
            included_plugins=None,
            skip_duplicated_oids=False,
            n_jobs=cpu_count() // 2,
            update_date=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_include_patterns_fail(self):
        sys.argv = ["troubadix", "--include-patterns", "troubadix/*"]

        with self.assertRaises(SystemExit):
            parse_args()

    def test_parse_files_non_recursive_fail(self):
        sys.argv = [
            "troubadix",
            "--files",
            "tests/plugins/test.nasl",
            "tests/plugins/fail2.nasl",
            "--non-recursive",
        ]

        with self.assertRaises(SystemExit):
            parse_args()

    def test_parse_exclude_patterns(self):
        sys.argv = ["troubadix", "-f", "--exclude-patterns", "troubadix/*"]
        expcected_dirs = [Path.cwd()]

        parsed_args = parse_args()

        expected_args = Namespace(
            full=True,
            dirs=expcected_dirs,
            files=None,
            from_file=None,
            commit_range=None,
            staged_only=False,
            no_statistic=False,
            verbose=0,
            log_file=None,
            non_recursive=False,
            exclude_patterns=["troubadix/*"],
            include_patterns=None,
            excluded_plugins=None,
            included_plugins=None,
            skip_duplicated_oids=False,
            n_jobs=cpu_count() // 2,
            update_date=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_max_cpu(self):
        sys.argv = [
            "troubadix",
            "-f",
            "--exclude-patterns",
            "troubadix/*",
            "-j",
            "1337",
        ]
        expcected_dirs = [Path.cwd()]

        parsed_args = parse_args()

        expected_args = Namespace(
            full=True,
            dirs=expcected_dirs,
            files=None,
            from_file=None,
            commit_range=None,
            staged_only=False,
            no_statistic=False,
            verbose=0,
            log_file=None,
            non_recursive=False,
            exclude_patterns=["troubadix/*"],
            include_patterns=None,
            excluded_plugins=None,
            included_plugins=None,
            skip_duplicated_oids=False,
            n_jobs=cpu_count(),
            update_date=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_min_cpu_update_date(self):
        sys.argv = [
            "troubadix",
            "-f",
            "--exclude-patterns",
            "troubadix/*",
            "-j",
            "-1337",
            "--update-date",
        ]
        expcected_dirs = [Path.cwd()]

        parsed_args = parse_args()

        expected_args = Namespace(
            full=True,
            dirs=expcected_dirs,
            files=None,
            from_file=None,
            commit_range=None,
            staged_only=False,
            no_statistic=False,
            verbose=0,
            log_file=None,
            non_recursive=False,
            exclude_patterns=["troubadix/*"],
            include_patterns=None,
            excluded_plugins=None,
            included_plugins=None,
            skip_duplicated_oids=False,
            n_jobs=cpu_count() // 2,
            update_date=True,
        )

        self.assertEqual(parsed_args, expected_args)

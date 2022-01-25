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

from argparse import Namespace
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

from naslinter.argparser import parse_args


class TestArgparsing(unittest.TestCase):
    def setUp(self):
        # store old arguments
        self.old_args = sys.argv
        self.term = Mock()

    def tearDown(self) -> None:
        # reset old arguments
        sys.argv = self.old_args

    def test_parse_full_debug_staged(self):
        sys.argv = ["naslinter", "-f", "--debug", "--staged-only"]
        expcected_dirs = [Path(os.getcwd())]

        parsed_args = parse_args(term=self.term)

        expected_args = Namespace(
            commit_range=None,
            debug=True,
            dirs=expcected_dirs,
            exclude_patterns=None,
            excluded_plugins=None,
            files=None,
            full=True,
            include_patterns=None,
            included_plugins=None,
            non_recursive=False,
            skip_duplicated_oids=False,
            staged_only=True,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_files(self):
        sys.argv = [
            "naslinter",
            "--files",
            "tests/plugins/test.nasl",
            "tests/plugins/fail2.nasl",
        ]

        parsed_args = parse_args(term=self.term)

        expected_args = Namespace(
            commit_range=None,
            debug=False,
            dirs=None,
            exclude_patterns=None,
            excluded_plugins=None,
            files=[
                Path("tests/plugins/test.nasl"),
                Path("tests/plugins/fail2.nasl"),
            ],
            full=False,
            include_patterns=None,
            included_plugins=None,
            non_recursive=False,
            skip_duplicated_oids=False,
            staged_only=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_dir_skip_duplicate(self):
        sys.argv = [
            "naslinter",
            "--dirs",
            "tests",
            "naslinter",
            "--skip-duplicated-oids",
            "--non-recursive",
        ]

        parsed_args = parse_args(term=self.term)

        expected_args = Namespace(
            commit_range=None,
            debug=False,
            dirs=[Path("tests"), Path("naslinter")],
            exclude_patterns=None,
            excluded_plugins=None,
            files=None,
            full=False,
            include_patterns=None,
            included_plugins=None,
            non_recursive=True,
            skip_duplicated_oids=True,
            staged_only=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_commit_range(self):
        sys.argv = ["naslinter", "--commit-range", "0123456", "7abcdef"]

        parsed_args = parse_args(term=self.term)

        expected_args = Namespace(
            commit_range=["0123456", "7abcdef"],
            debug=False,
            dirs=None,
            exclude_patterns=None,
            excluded_plugins=None,
            files=None,
            full=False,
            include_patterns=None,
            included_plugins=None,
            non_recursive=False,
            skip_duplicated_oids=False,
            staged_only=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_include_tests(self):
        sys.argv = [
            "naslinter",
            "--include-tests",
            "CheckBadwords",
            "UpdateModificationDate",
        ]

        parsed_args = parse_args(term=self.term)

        expected_args = Namespace(
            commit_range=None,
            debug=False,
            dirs=None,
            exclude_patterns=None,
            excluded_plugins=None,
            files=None,
            full=False,
            include_patterns=None,
            included_plugins=["CheckBadwords", "UpdateModificationDate"],
            non_recursive=False,
            skip_duplicated_oids=False,
            staged_only=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_exclude_tests(self):
        sys.argv = [
            "naslinter",
            "--exclude-tests",
            "CheckBadwords",
            "UpdateModificationDate",
        ]

        parsed_args = parse_args(term=self.term)

        expected_args = Namespace(
            commit_range=None,
            debug=False,
            dirs=None,
            exclude_patterns=None,
            excluded_plugins=["CheckBadwords", "UpdateModificationDate"],
            files=None,
            full=False,
            include_patterns=None,
            included_plugins=None,
            non_recursive=False,
            skip_duplicated_oids=False,
            staged_only=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_include_patterns(self):
        sys.argv = ["naslinter", "-f", "--include-patterns", "naslinter/*"]
        expcected_dirs = [Path(os.getcwd())]

        parsed_args = parse_args(term=self.term)

        expected_args = Namespace(
            commit_range=None,
            debug=False,
            dirs=expcected_dirs,
            exclude_patterns=None,
            excluded_plugins=None,
            files=None,
            full=True,
            include_patterns=["naslinter/*"],
            included_plugins=None,
            non_recursive=False,
            skip_duplicated_oids=False,
            staged_only=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_include_patterns_fail(self):
        sys.argv = ["naslinter", "--include-patterns", "naslinter/*"]

        with self.assertRaises(SystemExit):
            parse_args(term=self.term)

    def test_parse_files_non_recursive_fail(self):
        sys.argv = [
            "naslinter",
            "--files",
            "tests/plugins/test.nasl",
            "tests/plugins/fail2.nasl",
            "--non-recursive",
        ]

        with self.assertRaises(SystemExit):
            parse_args(term=self.term)

    def test_parse_exclude_patterns(self):
        sys.argv = ["naslinter", "-f", "--exclude-patterns", "naslinter/*"]
        expcected_dirs = [Path(os.getcwd())]

        parsed_args = parse_args(term=self.term)

        expected_args = Namespace(
            commit_range=None,
            debug=False,
            dirs=expcected_dirs,
            exclude_patterns=["naslinter/*"],
            excluded_plugins=None,
            files=None,
            full=True,
            include_patterns=None,
            included_plugins=None,
            non_recursive=False,
            skip_duplicated_oids=False,
            staged_only=False,
        )

        self.assertEqual(parsed_args, expected_args)

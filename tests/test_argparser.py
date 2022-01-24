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
from pathlib import Path
import sys
import unittest

from naslinter.argparser import parse_args


class TestArgparsing(unittest.TestCase):
    def setUp(self):
        # store old arguments
        self.old_args = sys.argv

    def tearDown(self) -> None:
        # reset old arguments
        sys.argv = self.old_args

    def test_parse_full(self):
        sys.argv = ["naslinter", "-f"]

        parsed_args = parse_args()

        expected_args = Namespace(
            commit_range=None,
            debug=False,
            dirs=None,
            exclude_regex=None,
            excluded_plugins=None,
            files=None,
            full=True,
            include_regex=None,
            included_plugins=None,
            non_recursive=False,
            skip_duplicated_oids=False,
            staged_only=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_files(self):
        sys.argv = [
            "naslinter",
            "--files",
            "tests/plugins/test.nasl",
            "tests/plugins/fail2.nasl",
        ]

        parsed_args = parse_args()

        expected_args = Namespace(
            commit_range=None,
            debug=False,  #
            dirs=None,
            exclude_regex=None,
            excluded_plugins=None,
            files=[
                Path("tests/plugins/test.nasl"),
                Path("tests/plugins/fail2.nasl"),
            ],
            full=False,
            include_regex=None,
            included_plugins=None,
            non_recursive=False,
            skip_duplicated_oids=False,
            staged_only=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_dir(self):
        sys.argv = ["naslinter", "--dirs", "tests", "naslinter"]

        parsed_args = parse_args()

        expected_args = Namespace(
            commit_range=None,
            debug=False,
            dirs=[Path("tests"), Path("naslinter")],
            exclude_regex=None,
            excluded_plugins=None,
            files=None,
            full=False,
            include_regex=None,
            included_plugins=None,
            non_recursive=False,
            skip_duplicated_oids=False,
            staged_only=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_commit_range(self):
        sys.argv = ["naslinter", "--commit-range", "0123456", "7abcdef"]

        parsed_args = parse_args()

        expected_args = Namespace(
            commit_range=["0123456", "7abcdef"],
            debug=False,
            dirs=None,
            exclude_regex=None,
            excluded_plugins=None,
            files=None,
            full=False,
            include_regex=None,
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

        parsed_args = parse_args()

        expected_args = Namespace(
            commit_range=None,
            debug=False,
            dirs=None,
            exclude_regex=None,
            excluded_plugins=None,
            files=None,
            full=False,
            include_regex=None,
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

        parsed_args = parse_args()

        expected_args = Namespace(
            commit_range=None,
            debug=False,
            dirs=None,
            exclude_regex=None,
            excluded_plugins=["CheckBadwords", "UpdateModificationDate"],
            files=None,
            full=False,
            include_regex=None,
            included_plugins=None,
            non_recursive=False,
            skip_duplicated_oids=False,
            staged_only=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_include_regex(self):
        sys.argv = ["naslinter", "-f", "--include-regex", "naslinter/*"]

        parsed_args = parse_args()

        expected_args = Namespace(
            commit_range=None,
            debug=False,
            dirs=None,
            exclude_regex=None,
            excluded_plugins=None,
            files=None,
            full=True,
            include_regex="naslinter/*",
            included_plugins=None,
            non_recursive=False,
            skip_duplicated_oids=False,
            staged_only=False,
        )

        self.assertEqual(parsed_args, expected_args)

    def test_parse_include_regex_fail(self):
        sys.argv = ["naslinter", "--include-regex", "naslinter/*"]

        with self.assertRaises(SystemExit):
            parse_args()

    def test_parse_exclude_regex(self):
        sys.argv = ["naslinter", "-f", "--exclude-regex", "naslinter/*"]

        parsed_args = parse_args()

        expected_args = Namespace(
            commit_range=None,
            debug=False,
            dirs=None,
            exclude_regex="naslinter/*",
            excluded_plugins=None,
            files=None,
            full=True,
            include_regex=None,
            included_plugins=None,
            non_recursive=False,
            skip_duplicated_oids=False,
            staged_only=False,
        )

        self.assertEqual(parsed_args, expected_args)

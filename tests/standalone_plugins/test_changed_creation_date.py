# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

import unittest
from argparse import Namespace
from os import chdir
from pathlib import Path
from subprocess import SubprocessError
from tempfile import TemporaryDirectory
from unittest.mock import patch

from troubadix.standalone_plugins.changed_creation_date import (
    check_changed_creation_date,
    git,
    main,
    parse_arguments,
)

TEST_COMMIT_RANGE = "main..test"
TEST_FILES = [Path("test.nasl")]


class TestChangedCreationDate(unittest.TestCase):

    @patch("troubadix.standalone_plugins.changed_creation_date.Path.exists")
    @patch("troubadix.standalone_plugins.changed_creation_date.git")
    def test_check_creation_date_ok(self, mock_git, mock_exists):

        mock_git.return_value = (
            '-script_tag(name:"creation_date",'
            ' value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");\n'
            '+script_tag(name:"creation_date",'
            ' value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");\n'
            "+test"
        )
        mock_exists.return_value = True

        self.assertFalse(
            check_changed_creation_date(TEST_COMMIT_RANGE, TEST_FILES)
        )

    @patch("troubadix.standalone_plugins.changed_creation_date.Path.exists")
    @patch("troubadix.standalone_plugins.changed_creation_date.git")
    def test_check_creation_date_fail(self, mock_git, mock_exists):

        mock_git.return_value = (
            '-script_tag(name:"creation_date",'
            ' value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");\n'
            '+script_tag(name:"creation_date",'
            ' value:"2020-03-04 10:00:00 +0200 (Wed, 04 Mar 2020)");'
        )
        mock_exists.return_value = True

        self.assertTrue(
            check_changed_creation_date(TEST_COMMIT_RANGE, TEST_FILES)
        )

    @patch("troubadix.standalone_plugins.changed_creation_date.Path.exists")
    @patch("troubadix.standalone_plugins.changed_creation_date.git")
    def test_creation_date_not_modified_lines_added(
        self, mock_git, mock_exists
    ):

        mock_git.return_value = (
            '-script_tag(name:"creation_date",'
            ' value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");\n'
            "test\n"
            '+script_tag(name:"creation_date",'
            ' value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");'
        )
        mock_exists.return_value = True

        self.assertFalse(
            check_changed_creation_date(TEST_COMMIT_RANGE, TEST_FILES)
        )

    @patch("troubadix.standalone_plugins.changed_creation_date.Path.exists")
    @patch("troubadix.standalone_plugins.changed_creation_date.git")
    def test_creation_date_not_modified_lines_removed(
        self, mock_git, mock_exists
    ):

        mock_git.return_value = (
            '-script_tag(name:"This got removed", value:"Nothing");'
        )
        mock_exists.return_value = True

        self.assertFalse(
            check_changed_creation_date(TEST_COMMIT_RANGE, TEST_FILES)
        )

    @patch("troubadix.standalone_plugins.changed_creation_date.Path.exists")
    @patch("troubadix.standalone_plugins.changed_creation_date.git")
    def test_creation_date_added_not_removed(self, mock_git, mock_exists):

        mock_git.return_value = (
            '+script_tag(name:"This got added", value:"Something");\n'
            '+script_tag(name:"creation_date", '
            ' value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");'
        )
        mock_exists.return_value = True

        self.assertFalse(
            check_changed_creation_date(TEST_COMMIT_RANGE, TEST_FILES)
        )

    def test_git_fail(self):
        with self.assertRaises(SubprocessError):
            git("blub")

    def test_git_ok(self):
        git("--version")

    @patch("troubadix.standalone_plugins.changed_creation_date.git")
    @patch(
        "troubadix.standalone_plugins.changed_creation_date.ArgumentParser.parse_args"
    )
    def test_args_ok(self, mock_parse_args, mock_git):

        mock_parse_args.return_value = Namespace(
            commit_range="main..test", files=[]
        )
        mock_git.return_value = "test1.nasl\ntest2.nasl\ntest3.txt"

        parsed_args = parse_arguments()

        self.assertEqual(parsed_args.commit_range, "main..test")
        self.assertEqual(
            parsed_args.files, [Path("test1.nasl"), Path("test2.nasl")]
        )

    def test_main_no_git_repository(self):
        cwd = Path.cwd()
        with TemporaryDirectory() as tempdir:
            try:
                chdir(tempdir)
                self.assertEqual(main(), 1)
            finally:
                chdir(cwd)

    @patch("troubadix.standalone_plugins.changed_creation_date.parse_arguments")
    @patch(
        "troubadix.standalone_plugins.changed_creation_date.check_changed_creation_date"
    )
    @patch("troubadix.standalone_plugins.changed_creation_date.os.chdir")
    @patch("troubadix.standalone_plugins.changed_creation_date.git")
    def test_main_check_creation_date_ok(
        self, mock_git, _, mock_check_creation_date, __
    ):

        mock_git.return_value = "test_directory"
        mock_check_creation_date.return_value = 0

        self.assertEqual(main(), 0)

    @patch("troubadix.standalone_plugins.changed_creation_date.parse_arguments")
    @patch(
        "troubadix.standalone_plugins.changed_creation_date.check_changed_creation_date"
    )
    @patch("troubadix.standalone_plugins.changed_creation_date.os.chdir")
    @patch("troubadix.standalone_plugins.changed_creation_date.git")
    def test_main_check_creation_date_fail(
        self, mock_git, _, mock_check_creation_date, __
    ):

        mock_git.return_value = "test_directory"
        mock_check_creation_date.return_value = 2

        self.assertEqual(main(), 2)


if __name__ == "__main__":
    unittest.main()

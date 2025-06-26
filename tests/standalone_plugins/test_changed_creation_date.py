# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

import unittest
from os import chdir
from pathlib import Path
from subprocess import SubprocessError
from tempfile import TemporaryDirectory

from troubadix.standalone_plugins.changed_creation_date import (
    check_changed_creation_date,
    git,
    main,
    parse_args,
)
from troubadix.standalone_plugins.util import temporary_git_directory


class TestChangedCreationDate(unittest.TestCase):

    def test_check_creation_date_ok(self):
        with temporary_git_directory() as tmpdir:

            test_file = tmpdir / "test.nasl"
            test_file.write_text(
                'script_tag(name:"creation_date", '
                'value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");'
            )
            git("add", str(test_file))
            git("commit", "-m", "test")
            git("checkout", "-b", "test")
            test_file.write_text(
                'script_tag(name:"creation_date", '
                'value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");\ntest'
            )
            git("add", "-u")
            git("commit", "-m", "test2")

            parsed_args = parse_args(["-c", "main..test"])
            self.assertFalse(check_changed_creation_date(parsed_args))

    def test_check_creation_date_fail(self):
        with temporary_git_directory() as tmpdir:

            test_file = tmpdir / "test.nasl"
            test_file.write_text(
                'script_tag(name:"creation_date", '
                'value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");'
            )
            git("add", str(test_file))
            git("commit", "-m", "test")
            git("checkout", "-b", "test")
            test_file.write_text(
                'script_tag(name:"creation_date", '
                'value:"2020-03-04 10:00:00 +0200 (Wed, 04 Mar 2020)");'
            )
            git("add", "-u")
            git("commit", "-m", "test2")

            parsed_args = parse_args(["-c", "main..test"])
            self.assertTrue(check_changed_creation_date(parsed_args))

    def test_not_nasl_file(self):
        with temporary_git_directory() as tmpdir:

            test_file = tmpdir / "test.txt"
            test_file.write_text(
                'script_tag(name:"creation_date", '
                'value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");'
            )
            git("add", str(test_file))
            git("commit", "-m", "test")
            git("checkout", "-b", "test")
            test_file.write_text(
                'script_tag(name:"creation_date", '
                'value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");\ntest'
            )
            git("add", "-u")
            git("commit", "-m", "test2")

            parsed_args = parse_args(["-c", "main..test"])
            self.assertFalse(check_changed_creation_date(parsed_args))

    def test_creation_date_not_modified_lines_added(self):
        with temporary_git_directory() as tmpdir:

            test_file = tmpdir / "test.nasl"
            test_file.write_text(
                'script_tag(name:"creation_date", '
                'value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");'
            )
            git("add", str(test_file))
            git("commit", "-m", "test")
            git("checkout", "-b", "test")
            test_file.write_text(
                "test\n"
                'script_tag(name:"creation_date", '
                'value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");'
            )
            git("add", "-u")
            git("commit", "-m", "test2")

            parsed_args = parse_args(["-c", "main..test"])
            self.assertFalse(check_changed_creation_date(parsed_args))

    def test_creation_date_not_modified_lines_removed(self):
        with temporary_git_directory() as tmpdir:

            test_file = tmpdir / "test.nasl"
            test_file.write_text(
                'script_tag(name:"creation_date", '
                'value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");\n'
                "test"
            )
            git("add", str(test_file))
            git("commit", "-m", "test")
            git("checkout", "-b", "test")
            test_file.write_text(
                'script_tag(name:"creation_date", '
                'value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");\n'
            )
            git("add", "-u")
            git("commit", "-m", "test2")

            parsed_args = parse_args(["-c", "main..test"])
            self.assertFalse(check_changed_creation_date(parsed_args))

    def test_creation_date_added_not_removed(self):
        with temporary_git_directory() as tmpdir:

            test_file = tmpdir / "test.nasl"
            test_file.write_text("test")
            git("add", str(test_file))
            git("commit", "-m", "test")
            git("checkout", "-b", "test")
            test_file.write_text(
                "test\n"
                'script_tag(name:"creation_date", '
                'value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");'
            )
            git("add", "-u")
            git("commit", "-m", "test2")

            parsed_args = parse_args(["-c", "main..test"])
            self.assertFalse(check_changed_creation_date(parsed_args))

    def test_git_fail(self):
        with self.assertRaises(SubprocessError):
            git("bla")

    def test_git_ok(self):
        git("--version")

    def test_args_ok(self):
        with temporary_git_directory() as tmpdir:

            test_file = tmpdir / "test.nasl"
            test_file.write_text(
                'script_tag(name:"creation_date", '
                'value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");'
            )
            git("add", str(test_file))
            git("commit", "-m", "test")
            git("checkout", "-b", "test")
            test_file.write_text(
                'script_tag(name:"creation_date", '
                'value:"2020-03-04 10:00:00 +0200 (Wed, 04 Mar 2020)");'
            )
            git("add", "-u")
            git("commit", "-m", "test2")

            self.assertEqual(
                parse_args(["-c", "main..test"]).commit_range, "main..test"
            )
            self.assertEqual(
                parse_args(["-c", "main..test", "-f", "test.nasl"]).files,
                [Path("test.nasl")],
            )

    def test_main_no_git_repository(self):
        cwd = Path.cwd()
        with TemporaryDirectory() as tempdir:
            try:
                chdir(tempdir)
                with unittest.mock.patch(
                    "sys.argv",
                    ["troubadix-changed-creation-date", "-c", "main..test"],
                ):
                    self.assertEqual(main(), 1)
            finally:
                chdir(cwd)

    def test_main_check_creation_date_ok(self):
        with temporary_git_directory() as tmpdir:

            test_file = tmpdir / "test.nasl"
            test_file.write_text(
                'script_tag(name:"creation_date", '
                'value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");'
            )
            git("add", str(test_file))
            git("commit", "-m", "test")
            git("checkout", "-b", "test")
            test_file.write_text(
                'script_tag(name:"creation_date", '
                'value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");\ntest'
            )
            git("add", "-u")
            git("commit", "-m", "test2")

            with unittest.mock.patch(
                "sys.argv",
                ["troubadix-changed-creation-date", "-c", "main..test"],
            ):
                self.assertEqual(main(), 0)

    def test_main_check_creation_date_fail(self):
        with temporary_git_directory() as tmpdir:

            test_file = tmpdir / "test.nasl"
            test_file.write_text(
                'script_tag(name:"creation_date", '
                'value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");'
            )
            git("add", str(test_file))
            git("commit", "-m", "test")
            git("checkout", "-b", "test")
            test_file.write_text(
                'script_tag(name:"creation_date", '
                'value:"2020-03-04 10:00:00 +0200 (Wed, 04 Mar 2020)");'
            )
            git("add", "-u")
            git("commit", "-m", "test2")

            with unittest.mock.patch(
                "sys.argv",
                ["troubadix-changed-creation-date", "-c", "main..test"],
            ):
                self.assertEqual(main(), 2)


if __name__ == "__main__":
    unittest.main()

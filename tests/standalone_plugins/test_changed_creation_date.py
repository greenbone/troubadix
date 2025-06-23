# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

import unittest
from pathlib import Path
from subprocess import SubprocessError

from troubadix.standalone_plugins.changed_creation_date import (
    check_creation_date,
    git,
    parse_args,
)
from troubadix.standalone_plugins.util import temporary_git_directory


def testgit(tmpdir: Path, ok: bool = False) -> None:
    test_file = tmpdir / "test.nasl"
    test_file.write_text(
        'script_tag(name:"creation_date", '
        'value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");'
    )
    git("add", str(test_file))
    git("commit", "-m", "test")
    git("checkout", "-b", "test")
    if ok:
        test_file.write_text(
            'script_tag(name:"creation_date", '
            'value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");\ntest'
        )
    else:
        test_file.write_text(
            'script_tag(name:"creation_date", '
            'value:"2020-03-04 10:00:00 +0200 (Wed, 04 Mar 2020)");'
        )
    git("add", "-u")
    git("commit", "-m", "test2")


class TestChangedCreationDate(unittest.TestCase):

    def test_check_creation_date_ok(self):
        with temporary_git_directory() as tmpdir:
            testgit(tmpdir, True)
            parsed_args = parse_args(["-c", "main..test"])
            self.assertFalse(check_creation_date(parsed_args))

    def test_check_creation_date_fail(self):
        with temporary_git_directory() as tmpdir:
            testgit(tmpdir)
            parsed_args = parse_args(["-c", "main..test"])
            self.assertTrue(check_creation_date(parsed_args))

    def test_git_fail(self):
        with self.assertRaises(SubprocessError):
            git("bla")

    def test_git_ok(self):
        git("--version")

    def test_args_ok(self):
        with temporary_git_directory() as tmpdir:
            testgit(tmpdir)
            self.assertEqual(
                parse_args(["-c", "main..test"]).commit_range, "main..test"
            )
            self.assertEqual(
                parse_args(["-c", "main..test", "-f", "test.nasl"]).files,
                [Path("test.nasl")],
            )


if __name__ == "__main__":
    unittest.main()

# Copyright (C) 2025 Greenbone AG
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from subprocess import SubprocessError
from typing import Generator

from troubadix.standalone_plugins.changed_creation_date import (
    check_creation_date,
    git,
    parse_args,
)


@contextmanager
def tempgitdir() -> Generator[Path, None, None]:
    cwd = Path.cwd()
    tempdir = tempfile.TemporaryDirectory()
    temppath = Path(tempdir.name)
    os.chdir(str(temppath))
    git("init", "-b", "main")
    git("config", "--local", "user.email", "max.mustermann@example.com")
    git("config", "--local", "user.name", "Max Mustermann")
    yield temppath
    tempdir.cleanup()
    os.chdir(str(cwd))


def testgit(tmpdir: Path, ok: bool = False) -> None:
    test_file = tmpdir / "test.nasl"
    test_file.write_text(
        'script_tag(name:"creation_date", '
        'value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025);'
    )
    git("add", str(test_file))
    git("commit", "-m", "test")
    git("checkout", "-b", "test")
    if ok:
        test_file.write_text(
            'script_tag(name:"creation_date", '
            'value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025);\ntest'
        )
    else:
        test_file.write_text(
            'script_tag(name:"creation_date", '
            'value:"2020-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)'
        )
    git("add", "-u")
    git("commit", "-m", "test2")


class TestChangedCreationDate(unittest.TestCase):

    def test_check_creation_date_ok(self):
        with tempgitdir() as tmpdir:
            testgit(tmpdir, True)
            parsed_args = parse_args(["-c", "main..test"])
            self.assertFalse(check_creation_date(parsed_args))

    def test_check_creation_date_fail(self):
        with tempgitdir() as tmpdir:
            testgit(tmpdir)
            parsed_args = parse_args(["-c", "main..test"])
            self.assertTrue(check_creation_date(parsed_args))

    def test_git_fail(self):
        with self.assertRaises(SubprocessError):
            git("bla")

    def test_git_ok(self):
        git("--version")

    def test_args_ok(self):
        with tempgitdir() as tmpdir:
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

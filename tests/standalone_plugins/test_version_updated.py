# Copyright (C) 2022 Greenbone Networks GmbH
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

import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from subprocess import SubprocessError
from typing import Generator
from unittest.mock import MagicMock, patch

from troubadix.standalone_plugins.version_updated import (
    check_version_updated,
    git,
)
from troubadix.standalone_plugins.version_updated import main as plugin_main
from troubadix.standalone_plugins.version_updated import parse_args


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


def setupgit(tmpdir: Path) -> None:
    test_file = tmpdir / "test.nasl"
    test_file.write_text(
        'script_version("2021-03-02T12:11:43+0000");”\n'
        'script_tag(name:"last_modification", '
        'value:"2021-03-02 12:11:43 +0000 (Tue, 02 Mar 2021)");\n'
    )
    git("add", str(test_file))
    git("commit", "-m", "test")


def change_nothing(tmpdir: Path) -> None:
    test_file = tmpdir / "test.nasl"
    test_file.write_text(
        'script_version("2021-03-02T12:11:43+0000");”\n'
        'script_tag(name:"last_modification", '
        'value:"2021-03-02 12:11:43 +0000 (Tue, 02 Mar 2021)");123\n'
    )
    git("add", str(test_file))
    git("commit", "-m", "test_nothing")


def change_version(tmpdir: Path):
    test_file = tmpdir / "test.nasl"
    test_file.write_text(
        'script_version("2021-03-02T12:11:43+0001");”\n'
        'script_tag(name:"last_modification", '
        'value:"2021-03-02 12:11:43 +0000 (Tue, 02 Mar 2021)");\n'
    )
    git("add", str(test_file))
    git("commit", "-m", "test_version")


def change_last_modification(tmpdir: Path):
    test_file = tmpdir / "test.nasl"
    test_file.write_text(
        'script_version("2021-03-02T12:11:43+0000");”\n'
        'script_tag(name:"last_modification", '
        'value:"2021-03-02 12:11:43 +0010 (Tue, 02 Mar 2021)");\n'
    )
    git("add", str(test_file))
    git("commit", "-m", "test_last_modification")


def change_version_and_last_modification(tmpdir: Path):
    test_file = tmpdir / "test.nasl"
    test_file.write_text(
        'script_version("2021-03-02T12:11:43+0001");\n'
        'script_tag(name:"last_modification", '
        'value:"2021-03-02 12:11:43 +0001 (Tue, 02 Mar 2021)");\n'
    )
    git("add", str(test_file))
    git("commit", "-m", "test_both")


def get_mocked_arguments():
    mock = MagicMock()
    mock.commit_range = "HEAD~1"
    mock.files = []

    return mock


class TestVersionChanged(unittest.TestCase):
    def test_change_nothing(self):
        with tempgitdir() as tmpdir:
            setupgit(tmpdir)
            change_nothing(tmpdir)
            parsed_args = parse_args(["-c", "HEAD~1"])
            self.assertFalse(
                check_version_updated(
                    parsed_args.files, parsed_args.commit_range
                )
            )

    def test_change_version(self):
        with tempgitdir() as tmpdir:
            setupgit(tmpdir)
            change_version(tmpdir)
            parsed_args = parse_args(["-c", "HEAD~1"])
            self.assertFalse(
                check_version_updated(
                    parsed_args.files, parsed_args.commit_range
                )
            )

    def test_change_last_modification(self):
        with tempgitdir() as tmpdir:
            setupgit(tmpdir)
            change_last_modification(tmpdir)
            parsed_args = parse_args(["-c", "HEAD~1"])
            self.assertFalse(
                check_version_updated(
                    parsed_args.files, parsed_args.commit_range
                )
            )

    def test_change_both(self):
        with tempgitdir() as tmpdir:
            setupgit(tmpdir)
            change_version_and_last_modification(tmpdir)
            parsed_args = parse_args(["-c", "HEAD~1"])
            self.assertTrue(
                check_version_updated(
                    parsed_args.files, parsed_args.commit_range
                )
            )

    def test_git_fail(self):
        with self.assertRaises(SubprocessError):
            git("bla")

    def test_git_ok(self):
        git("--version")

    def test_args_ok(self):
        with tempgitdir() as tmpdir:
            setupgit(tmpdir)
            self.assertEqual(parse_args(["-c", "HEAD"]).commit_range, "HEAD")
            self.assertEqual(
                parse_args(["-c", "HEAD", "-f", "test.nasl"]).files,
                [Path("test.nasl")],
            )

    @patch("troubadix.standalone_plugins.version_updated.parse_args")
    def test_main_ok(self, mock_args):
        mock_args.return_value = get_mocked_arguments()
        with tempgitdir() as tmpdir:
            setupgit(tmpdir)
            change_version_and_last_modification(tmpdir)

            exit_code = plugin_main()

            self.assertEqual(exit_code, 0)

    @patch("troubadix.standalone_plugins.version_updated.parse_args")
    def test_main_nok(self, mock_args):
        mock_args.return_value = get_mocked_arguments()
        with tempgitdir() as tmpdir:
            setupgit(tmpdir)
            change_version(tmpdir)

            exit_code = plugin_main()

            self.assertEqual(exit_code, 2)


if __name__ == "__main__":
    unittest.main()

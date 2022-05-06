#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
#  test_changed_oid.py
#
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
import unittest
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Generator
from troubadix.standalone_plugins.changed_oid import check_oid, git, parse_args


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


def testgit(tmpdir: Path) -> None:
    test_file = tmpdir / "test.nasl"
    test_file.write_text('script_oid("1.3.6.1.4.1.25623.1.0.100313");')
    git("add", str(test_file))
    git("commit", "-m", "test")
    git("checkout", "-b", "test")
    test_file.write_text('script_oid("2.3.6.1.4.1.25623.1.0.100313");')
    git("add", "-u")
    git("commit", "-m", "test2")


class TestChangeOid(unittest.TestCase):
    def test_check_oid(self):
        with tempgitdir() as tmpdir:
            testgit(tmpdir)
            parsed_args = parse_args(["-c", "main..test"])
            results = check_oid(parsed_args)
            self.assertEqual(len(list(results)), 1)


if __name__ == "__main__":
    unittest.main()

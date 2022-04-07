# Copyright (C) 2021-2022 Greenbone Networks GmbH
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
import re
from pathlib import Path
from subprocess import PIPE, Popen
from typing import List, Optional, Union, Tuple, AnyStr

# Script categories
SCRIPT_CATEGORIES = {
    "ACT_INIT": 0,
    "ACT_SCANNER": 1,
    "ACT_SETTINGS": 2,
    "ACT_GATHER_INFO": 3,
    "ACT_ATTACK": 4,
    "ACT_MIXED_ATTACK": 5,
    "ACT_DESTRUCTIVE_ATTACK": 6,
    "ACT_DENIAL": 7,
    "ACT_KILL_HOST": 8,
    "ACT_FLOOD": 9,
    "ACT_END": 10,
}

# Root directory of nasl files
_ROOT = "nasl"


def is_ignore_file(
    file_name: Union[Path, str], ignore_files: Union[List[Path], List[str]]
) -> bool:
    for ignore_file in ignore_files:
        if str(ignore_file) in str(file_name):
            return True
    return False


def get_path_from_root(file_name: Path, root: Path = None):
    file_name = file_name.resolve()
    if not root:
        root = get_root(file_name)
    return file_name.relative_to(root)


# https://stackoverflow.com/questions/377017/test-if-executable-exists-in-python
def which(program: Union[Path, str]) -> Optional[Path]:
    def is_exe(fpath: Path):
        if isinstance(fpath, str):
            fpath = Path(fpath)
        return fpath.is_file() and os.access(fpath, os.X_OK)

    if isinstance(program, (Path, str)) and is_exe(program):
        return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = Path(path) / program
            if is_exe(exe_file):
                return exe_file

    return None


def subprocess_cmd(command: str, encoding="UTF-8") -> Tuple[AnyStr, AnyStr]:
    def any2str(str_input: AnyStr) -> str:
        if isinstance(str_input, bytes):
            return str_input.decode(encoding).strip()
        elif isinstance(str_input, str):
            return str_input.strip()
        return ""

    process = Popen(
        command,
        stdout=PIPE,
        shell=True,
        encoding=encoding,
    )
    proc_stdout, proc_stderr = process.communicate()

    return any2str(proc_stdout), any2str(proc_stderr)


class Root:
    instance = False

    def __init__(self, path: Path, root: str = _ROOT) -> None:
        match = re.search(
            rf"(?P<path>/([\w\-\.\\ ]+/)+{root}/[\w\-\.]+/)",
            str(path.resolve()),
        )
        if match:
            self.root = Path(match.group("path"))
            if not self.root.exists():
                self.root = None
        else:
            self.root = None
        self.instance = self


def get_root(path: Path) -> Optional[Path]:
    """Get the root directory of the VTs"""
    if Root.instance:
        return Root.instance.root
    return Root(path).root

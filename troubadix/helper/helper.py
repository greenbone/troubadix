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
from pathlib import Path
from subprocess import PIPE, Popen
from typing import AnyStr, List, Optional, Tuple, Union

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


def is_ignore_file(
    file_name: Union[Path, str], ignore_files: Union[List[Path], List[str]]
) -> bool:
    for ignore_file in ignore_files:
        if str(ignore_file) in str(file_name):
            return True
    return False


ENTERPRISE_FOLDERS = (
    "enterprise",
    "gsf",
)

# Supported feed directories
FEED_VERSIONS = ["common", "21.04", "22.04", ""]


def is_enterprise_folder(folder: Union[Path, str]) -> bool:
    return str(folder) in ENTERPRISE_FOLDERS


def get_path_from_root(file_name: Path, root: Path):
    file_name = file_name.resolve()
    return file_name.relative_to(root.absolute())


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


def get_root(path: Path) -> Path:
    """Get the root directory of the VTs"""
    path = path.resolve().absolute()
    for parent in path.parents:
        if parent.name in ["", "nasl"]:
            return parent

    return path

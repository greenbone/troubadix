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

import re
from subprocess import Popen, PIPE
from pathlib import Path
from typing import List, Optional, Union


# Root directory of nasl files
_ROOT = "nasl"


def is_ignore_file(
    file_name: Union[Path, str], ignore_files: Union[List[Path], List[str]]
) -> bool:
    for ignore_file in ignore_files:
        if str(ignore_file) in str(file_name):
            return True
    return False


def subprocess_cmd(command: str) -> str:
    process = Popen(command, stdout=PIPE, shell=True)
    proc_stdout = process.communicate()[0].strip()
    return proc_stdout.decode("utf-8")


class Root:
    instance = False

    def __init__(self, path: Path, root: str = _ROOT) -> None:
        match = re.search(
            rf"(?P<path>/([a-zA-Z0-9\-\_\.]+/)+{root}/[a-zA-Z0-9\-\_]+/)",
            str(path),
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

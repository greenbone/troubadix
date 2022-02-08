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

from pathlib import Path
import re
from typing import List, Union

OPENVAS_OID_PREFIX = "1.3.6.1.4.1.25623.1.[0-9]+."


def is_ignore_file(
    file_name: Union[Path, str], ignore_files: Union[List[Path], List[str]]
) -> bool:
    for ignore_file in ignore_files:
        if str(ignore_file) in str(file_name):
            return True
    return False


def find_oid(line: str) -> Union[None, str]:
    """Find the OID in the the given line"""
    match = re.search(r"script_id\s*\(\s*([0-9]+)\s*\)", line)
    if match:
        return f"{OPENVAS_OID_PREFIX}{match.group(1)}"
    match = re.search(
        r'SCRIPT_OID\s*=\s*(?P<quote>[\'"])(?P<oid>[0-9.]+)(?P=quote)', line
    )
    if match:
        return match.group("oid")
    match = re.search(
        r'script_oid\s*\(\s*(?P<quote>[\'"])(?P<oid>[0-9.]+)(?P=quote)\s*\)',
        line,
    )
    if match:
        return match.group("oid")
    return None

# Copyright (C) 2021 Greenbone AG
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

from stat import filemode
from typing import Iterator

from troubadix.plugin import FilePlugin, LinterError, LinterResult


class CheckVTFilePermissions(FilePlugin):
    """This script checks whether the nasl file
    has the correct file permissions
    """

    name = "check_vt_file_permissions"

    def run(self) -> Iterator[LinterResult]:
        permissions = filemode(self.context.nasl_file.stat().st_mode)

        if "x" in permissions:
            yield LinterError(
                f"VT has invalid file permissions: {permissions}.\n"
                "NASL scripts must not be executable.\n"
                "Typical file permissions are '644' (-rw-r--r-) "
                "and `664` (-rw-rw-r-)",
                file=self.context.nasl_file,
                plugin=self.name,
            )

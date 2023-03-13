# Copyright (C) 2023 Greenbone AG
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
from typing import List

from troubadix.standalone_plugins.changed_packages.package import (
    Direction,
    Package,
    Reasons,
)

from .marker import Marker

PACKAGE_UPDATE_SUFFIX_PATTERN = re.compile(r"(?P<update>\d+)$")


class ChangedUpdate(Marker):
    @classmethod
    def mark(cls, missing_packages: List[Package], new_packages: List[Package]):
        for package in new_packages:
            match = PACKAGE_UPDATE_SUFFIX_PATTERN.search(package.version)
            if not match:
                continue

            suffix = match.group("update")
            other_package = next(
                (
                    old_package
                    for old_package in missing_packages
                    if package.name == old_package.name
                    and old_package.version.startswith(
                        package.version.replace(suffix, "")
                    )
                    and package.release == old_package.release
                ),
                None,
            )

            if not other_package:
                continue

            package.reasons[Reasons.CHANGED_UPDATE] = Direction.ACTIVE
            other_package.reasons[Reasons.CHANGED_UPDATE] = Direction.ACTIVE

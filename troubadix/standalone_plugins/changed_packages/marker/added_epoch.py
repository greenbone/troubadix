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

from troubadix.standalone_plugins.changed_packages.marker.marker import Marker
from troubadix.standalone_plugins.changed_packages.package import (
    Direction,
    Package,
    Reasons,
)

PACKAGE_EPOCH_PATTERN = re.compile(r"^(?P<epoch>\d+):")


class AddedEpoch(Marker):
    @classmethod
    def mark(cls, missing_packages: List[Package], new_packages: List[Package]):
        for package in new_packages:
            match = PACKAGE_EPOCH_PATTERN.search(package.version)
            if not match:
                continue

            epoch = match.group("epoch")
            other_package = cls._find_package(
                Package(
                    package.name,
                    package.version.replace(epoch + ":", ""),
                    package.release,
                ),
                missing_packages,
            )

            if not other_package:
                continue

            package.reasons[Reasons.ADDED_EPOCH] = Direction.ACTIVE
            other_package.reasons[Reasons.ADDED_EPOCH] = Direction.PASSIVE

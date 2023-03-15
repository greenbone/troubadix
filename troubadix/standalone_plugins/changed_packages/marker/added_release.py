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

from typing import List

from troubadix.standalone_plugins.changed_packages.package import (
    Direction,
    Package,
    Reasons,
)

from .marker import Marker


class AddedRelease(Marker):
    @staticmethod
    def mark(old_packages: List[Package], new_packages: List[Package]):
        # Example: ...2015/debian/deb_3257.nasl now has DEB8 next to DEB7
        new_releases = set([package.release for package in new_packages])
        old_releases = set([package.release for package in old_packages])

        for new_release in new_releases.difference(old_releases):
            for package in new_packages:
                if package.release != new_release:
                    continue

                package.reasons[Reasons.ADDED_RELEASE] = Direction.ACTIVE

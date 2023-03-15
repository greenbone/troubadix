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

from typing import Iterable

from troubadix.standalone_plugins.changed_packages.package import Package


class Marker:
    @staticmethod
    def _find_package(package: Package, packages: Iterable[Package]):
        result = next(
            (
                other_package
                for other_package in packages
                if other_package.name == package.name
                and other_package.version == package.version
                and other_package.release == package.release
            ),
            None,
        )
        return result

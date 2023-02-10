# Copyright (C) 2023 Greenbone Networks GmbH
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

from unittest import TestCase

from troubadix.standalone_plugins.changed_packages.package import (
    Package,
    Reasons,
)


class ReasonsTextCase(TestCase):
    def test_from_cli_argument(self):
        self.assertEqual(
            Reasons.DROPPED_ARCHITECTURE,
            Reasons.from_cli_argument("dropped-architecture"),
        )


class PackageTestCase(TestCase):
    def test_lt(self):
        package = Package("a-foo", "1.2.3", "DEB11")
        other_package = Package("b-foo", "1.2.3", "DEB11")

        self.assertLess(package, other_package)

        package = Package("foo", "1.2.3", "DEB11")
        other_package = Package("foo", "2.2.3", "DEB11")

        print(
            (package.release, package.name, package.version)
            < (other_package.release, other_package.name, other_package.version)
        )

        self.assertLess(package, other_package)

        package = Package("foo", "1.2.3", "DEB10")
        other_package = Package("foo", "1.2.3", "DEB11")

        self.assertLess(package, other_package)

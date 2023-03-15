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

from unittest import TestCase

from troubadix.standalone_plugins.changed_packages.changed_packages import (
    filter_reasons,
    get_packages,
)
from troubadix.standalone_plugins.changed_packages.package import (
    Direction,
    Package,
    Reasons,
)


class ChangedPackagesTestCase(TestCase):
    def test_get_package(self):
        content = """
        ...some NASL...
        if(!isnull(res = isdpkgvuln(pkg:"libwpewebkit-1.0-3", ver:"2.38.3-1~deb11u1", rls:"DEB11"))) {
            report += res;
        }
        if(!isnull(res = isdpkgvuln(pkg:"libwpewebkit-1.0-dev", ver:"2.38.3-1~deb11u1", rls:"DEB11"))) {
            report += res;
        }
        if(!isnull(res = isdpkgvuln(pkg:"libwpewebkit-1.0-doc", ver:"2.38.3-1~deb11u1", rls:"DEB11"))) {
            report += res;
        }
        if(!isnull(res = isdpkgvuln(pkg:"wpewebkit-driver", ver:"2.38.3-1~deb11u1", rls:"DEB11"))) {
            report += res;
        }
        ...some more NASL...
        """

        result = get_packages(content)

        expected_result = {
            Package("libwpewebkit-1.0-3", "2.38.3-1~deb11u1", "DEB11"),
            Package("libwpewebkit-1.0-dev", "2.38.3-1~deb11u1", "DEB11"),
            Package("libwpewebkit-1.0-doc", "2.38.3-1~deb11u1", "DEB11"),
            Package("wpewebkit-driver", "2.38.3-1~deb11u1", "DEB11"),
        }

        self.assertEqual(expected_result, result)

    def test_get_package_duplicate(self):
        content = """
        ...some NASL...
        if(!isnull(res = isdpkgvuln(pkg:"foo", ver:"1.2.3", rls:"DEB10"))) {
            report += res;
        }
        if(!isnull(res = isdpkgvuln(pkg:"bar", ver:"1.2.3", rls:"DEB10"))) {
            report += res;
        }
        if(!isnull(res = isdpkgvuln(pkg:"foo", ver:"1.2.3", rls:"DEB10"))) {
            report += res;
        }
        ...some more NASL...
        """

        with self.assertRaises(Exception):
            get_packages(content)

    def test_filter_reasons(self):
        packages = [
            Package(
                "foo", "1.2.3", "DEB11", {Reasons.ADDED_EPOCH: Direction.ACTIVE}
            ),
            Package(
                "bar",
                "1.2.3",
                "DEB11",
                {
                    Reasons.ADDED_EPOCH: Direction.ACTIVE,
                    Reasons.ADDED_RELEASE: Direction.PASSIVE,
                },
            ),
            Package(
                "baz", "1.2.3", "DEB11", {Reasons.ADDED_UDEB: Direction.ACTIVE}
            ),
        ]

        expected_packages = [
            Package(
                "bar",
                "1.2.3",
                "DEB11",
                {
                    Reasons.ADDED_EPOCH: Direction.ACTIVE,
                    Reasons.ADDED_RELEASE: Direction.PASSIVE,
                },
            ),
            Package(
                "baz", "1.2.3", "DEB11", {Reasons.ADDED_UDEB: Direction.ACTIVE}
            ),
        ]

        result = filter_reasons(packages, [Reasons.ADDED_EPOCH])

        self.assertEqual(expected_packages, result)

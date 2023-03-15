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

from troubadix.standalone_plugins.changed_packages.marker import ChangedUpdate
from troubadix.standalone_plugins.changed_packages.package import (
    Direction,
    Package,
    Reasons,
)


class ChangedUpdateTestCase(TestCase):
    def test_mark(self):
        missing_packages = [
            Package("foo", "1.2.3", "DEB11"),
            Package("bar", "4.5.6-deb11u1", "DEB11"),
        ]
        new_packages = [
            Package("foo", "1.2.4", "DEB11"),
            Package("bar", "4.5.6-deb11u2", "DEB11"),
        ]

        expected_missing_packages = [
            Package(
                "foo",
                "1.2.3",
                "DEB11",
                {Reasons.CHANGED_UPDATE: Direction.ACTIVE},
            ),
            Package(
                "bar",
                "4.5.6-deb11u1",
                "DEB11",
                {Reasons.CHANGED_UPDATE: Direction.ACTIVE},
            ),
        ]
        expected_new_packages = [
            Package(
                "foo",
                "1.2.4",
                "DEB11",
                {Reasons.CHANGED_UPDATE: Direction.ACTIVE},
            ),
            Package(
                "bar",
                "4.5.6-deb11u2",
                "DEB11",
                {Reasons.CHANGED_UPDATE: Direction.ACTIVE},
            ),
        ]

        ChangedUpdate.mark(missing_packages, new_packages)

        self.assertEqual(expected_missing_packages, missing_packages)
        self.assertEqual(expected_new_packages, new_packages)

    def test_mark_no_match(self):
        missing_packages = [Package("foo", "1.2.3a", "DEB11")]
        new_packages = [Package("foo", "1.2.3a", "DEB11")]

        expected_missing_packages = [Package("foo", "1.2.3a", "DEB11")]
        expected_new_packages = [Package("foo", "1.2.3a", "DEB11")]

        ChangedUpdate.mark(missing_packages, new_packages)

        self.assertEqual(expected_missing_packages, missing_packages)
        self.assertEqual(expected_new_packages, new_packages)

    def test_mark_no_other_package(self):
        missing_packages = [Package("foo", "1.2.3", "DEB11")]
        new_packages = [Package("foo", "1.2.3-deb11u2", "DEB11")]

        expected_missing_packages = [Package("foo", "1.2.3", "DEB11")]
        expected_new_packages = [Package("foo", "1.2.3-deb11u2", "DEB11")]

        ChangedUpdate.mark(missing_packages, new_packages)

        self.assertEqual(expected_missing_packages, missing_packages)
        self.assertEqual(expected_new_packages, new_packages)

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

import unittest

from naslinter.plugin import LinterError
from naslinter.plugins.creation_date import CheckCreationDate


class CheckCreationDateTestCase(unittest.TestCase):
    def test_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"creation_date", value:"2013-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2013)")'
        )

        results = list(CheckCreationDate.run(path, content.splitlines()))
        self.assertEqual(len(results), 0)

    def test_missing(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"7.5");\n'
            'script_tag(name:"cvss_base_vector", '
            'value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");'
        )

        results = list(CheckCreationDate.run(path, content.splitlines()))
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "No creation date has been found in VT 'some/file.nasl'.",
            results[0].message,
        )

    def test_wrong_weekday(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"creation_date", value:"2013-05-14 11:24:55 +0200 '
            '(Mon, 14 May 2013)");'
        )

        results = list(CheckCreationDate.run(path, content.splitlines()))
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "Wrong day of week in VT 'some/file.nasl'. Please change it from "
            "'Mon' to 'Tue'.",
            results[0].message,
        )

    def test_no_timezone(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"creation_date", value:"2013-05-14 11:24:55 '
            '(Tue, 14 May 2013)");'
        )

        results = list(CheckCreationDate.run(path, content.splitlines()))
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "False or incorrectly formatted creation_date of VT "
            "'some/file.nasl'",
            results[0].message,
        )

    def test_different_dates(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"creation_date", value:"2013-05-14 11:24:55 +0200 '
            '(Tue, 15 May 2013)");'
        )

        results = list(CheckCreationDate.run(path, content.splitlines()))
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "The creation_date of VT 'some/file.nasl' consists of two "
            "different dates.",
            results[0].message,
        )

    def test_wrong_length(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"creation_date", value:"2013-05-14 11:24:55 +0200 '
            '(Tue, 14 May 2013 )");'
        )

        results = list(CheckCreationDate.run(path, content.splitlines()))
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "Incorrectly formatted creation_date of VT 'some/file.nasl' "
            "(length != 44). Please use EXACTLY the following format as in: "
            '"2017-11-29 13:56:41 +0000 (Wed, 29 Nov 2017)"',
            results[0].message,
        )

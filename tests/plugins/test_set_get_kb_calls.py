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
from naslinter.plugins.set_get_kb_calls import CheckSetGetKbCalls


class CheckSetGetKbCallsTestCase(unittest.TestCase):
    path = Path("some/file.nasl")

    def test_ok(self):

        content = """
set_kb_item(name:"kb/key", value:"value");
replace_kb_item(name:"kb/key", value:"value");
get_kb_item("kb/key");
get_kb_list("kb/key");
"""

        results = list(CheckSetGetKbCalls.run(self.path, content))
        self.assertEqual(len(results), 0)

    def test_wrong_calls(self):

        content = """
set_kb_item("kb/key", value:"value");
replace_kb_item(name:"kb/key", "value");
replace_kb_item(name:"kb/key");
replace_kb_item(name:"kb/key", name:"kb/key");
get_kb_item(name:"kb/key");
"""

        results = list(CheckSetGetKbCalls.run(self.path, content))
        self.assertEqual(len(results), 5)

    def test_output_set(self):

        content = """
set_kb_item("kb/key", value:"value");
"""

        results = list(CheckSetGetKbCalls.run(self.path, content))
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertIn(
            'set_kb_item("kb/key", value:"value");: missing name or value'
            " parameter",
            results[0].message,
        )

    def test_output_get(self):

        content = """
get_kb_item("kb/key", value:"value");
"""

        results = list(CheckSetGetKbCalls.run(self.path, content))
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertIn(
            'get_kb_item("kb/key", value:"value");: should not contain'
            " parameter names",
            results[0].message,
        )

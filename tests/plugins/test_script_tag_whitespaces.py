# Copyright (C) 2022 Greenbone Networks GmbH
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
from naslinter.plugins.script_tag_whitespaces import CheckScriptTagWhitespaces


class CheckScriptTagWhitespacesTestCase(unittest.TestCase):
    path = Path("some/file.nasl")

    def test_ok(self):

        content = 'script_tag(name: "foo", value:"bar");'

        results = list(CheckScriptTagWhitespaces.run(self.path, content))
        self.assertEqual(len(results), 0)

    def test_leading_whitespace(self):
        content = 'script_tag(name: "foo", value:" bar");'

        results = list(CheckScriptTagWhitespaces.run(self.path, content))
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            'script_tag(name: "foo", value:" bar");: value contains a leading'
            " or trailing whitespace character",
            results[0].message,
        )

    def test_trailing_whitespace(self):
        content = 'script_tag(name: "foo", value:"bar\n");'

        results = list(CheckScriptTagWhitespaces.run(self.path, content))
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
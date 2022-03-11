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
from naslinter.plugins.script_calls_empty_values import (
    CheckScriptCallsEmptyValues,
)


class CheckScriptCallsEmptyValuesTestCase(unittest.TestCase):
    path = Path("some/file.nasl")

    def test_ok(self):

        content = (
            "script_category(ACT_INIT);\n"
            'script_xref(name: "URL", value:"http://example.com");\n'
            'script_tag(name:"foo", value:"bar");\n'
            'script_add_preferences("");'
        )

        results = list(CheckScriptCallsEmptyValues.run(self.path, content))
        self.assertEqual(len(results), 0)

    def test_missing_values(self):
        content = (
            'script_category("");\n'
            'script_xref(name: "URL",value:"");\n'
            'script_tag(name:"", value:"");'
        )

        results = list(CheckScriptCallsEmptyValues.run(self.path, content))
        self.assertEqual(len(results), 3)
        self.assertIsInstance(results[0], LinterError)
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

from naslinter.plugin import LinterWarning
from naslinter.plugins.script_calls_recommended import (
    CheckScriptCallsRecommended,
)


class CheckScriptCallsRecommendedTestCase(unittest.TestCase):
    path = Path("some/file.nasl")

    def test_ok(self):

        content = (
            "script_dependencies();\n"
            "script_require_ports();\n"
            "script_require_udp_ports();\n"
            "script_require_keys();\n"
            "script_mandatory_keys();"
        )

        results = list(CheckScriptCallsRecommended.run(self.path, content))
        self.assertEqual(len(results), 0)

    def test_missing_calls(self):
        content = 'script_xref(name: "URL", value:"");'

        results = list(CheckScriptCallsRecommended.run(self.path, content))
        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], LinterWarning)

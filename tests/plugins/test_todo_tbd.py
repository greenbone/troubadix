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

from troubadix.plugin import LinterWarning
from troubadix.plugins import CheckTodoTbd

from . import PluginTestCase


class CheckTodoTbdTestCase(PluginTestCase):
    def test_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"summary", value:"TBD");\n'
            'script_tag(name:"solution", value:"TODO");\n'
            'script_tag(name:"impact", value:"@todo");\n'
        )
        results = list(
            CheckTodoTbd.run(
                path,
                content.splitlines(),
            )
        )
        self.assertEqual(len(results), 0)

    def test_ignore(self):
        path = Path("http_func.inc")
        content = (
            "#TBD"
            'script_tag(name:"summary", value:"A value");#TBD\n'
            'script_tag(name:"solution", value:"A value");\n'
            'script_tag(name:"impact", value:"A value");\n'
        )
        results = list(
            CheckTodoTbd.run(
                path,
                content.splitlines(),
            )
        )
        self.assertEqual(len(results), 0)

    def test_tbd(self):
        path = Path("some/file.nasl")
        content = (
            "##TBD\n"
            'script_tag(name:"summary", value:"A value");#TBD\n'
            'script_tag(name:"solution", value:"A value");\n'
            'script_tag(name:"impact", value:"A value");\n'
        )
        results = list(
            CheckTodoTbd.run(
                path,
                content.splitlines(),
            )
        )
        self.assertEqual(len(results), 2)

        self.assertIsInstance(results[0], LinterWarning)
        self.assertEqual(
            "VT some/file.nasl contains #TODO/TBD/@todo keywords at line 1",
            results[0].message,
        )

        self.assertIsInstance(results[1], LinterWarning)
        self.assertEqual(
            "VT some/file.nasl contains #TODO/TBD/@todo keywords at line 2",
            results[1].message,
        )

    def test_todo(self):
        path = Path("some/file.nasl")
        content = (
            "##TODO\n"
            'script_tag(name:"summary", value:"A value");#TBD\n'
            'script_tag(name:"solution", value:"A value");\n'
            'script_tag(name:"impact", value:"A value");\n'
        )
        results = list(
            CheckTodoTbd.run(
                path,
                content.splitlines(),
            )
        )
        self.assertEqual(len(results), 2)

        self.assertIsInstance(results[0], LinterWarning)
        self.assertEqual(
            "VT some/file.nasl contains #TODO/TBD/@todo keywords at line 1",
            results[0].message,
        )

        self.assertIsInstance(results[1], LinterWarning)
        self.assertEqual(
            "VT some/file.nasl contains #TODO/TBD/@todo keywords at line 2",
            results[1].message,
        )

    def test_at_todo(self):
        path = Path("some/file.nasl")
        content = (
            "##@todo\n"
            'script_tag(name:"summary", value:"A value");#@todo\n'
            'script_tag(name:"solution", value:"A value");\n'
            'script_tag(name:"impact", value:"A value");\n'
        )
        results = list(
            CheckTodoTbd.run(
                path,
                content.splitlines(),
            )
        )
        self.assertEqual(len(results), 2)

        self.assertIsInstance(results[0], LinterWarning)
        self.assertEqual(
            "VT some/file.nasl contains #TODO/TBD/@todo keywords at line 1",
            results[0].message,
        )

        self.assertIsInstance(results[1], LinterWarning)
        self.assertEqual(
            "VT some/file.nasl contains #TODO/TBD/@todo keywords at line 2",
            results[1].message,
        )

    def test_mixed(self):
        path = Path("some/file.nasl")
        content = (
            "##TBD\n"
            'script_tag(name:"summary", value:"A value");#TODO\n'
            'script_tag(name:"solution", value:"A value");\n'
            'script_tag(name:"impact", value:"A value");##@todo\n'
        )
        results = list(
            CheckTodoTbd.run(
                path,
                content.splitlines(),
            )
        )
        self.assertEqual(len(results), 3)

        self.assertIsInstance(results[0], LinterWarning)
        self.assertEqual(
            "VT some/file.nasl contains #TODO/TBD/@todo keywords at line 1",
            results[0].message,
        )

        self.assertIsInstance(results[1], LinterWarning)
        self.assertEqual(
            "VT some/file.nasl contains #TODO/TBD/@todo keywords at line 2",
            results[1].message,
        )

        self.assertIsInstance(results[2], LinterWarning)
        self.assertEqual(
            "VT some/file.nasl contains #TODO/TBD/@todo keywords at line 4",
            results[2].message,
        )

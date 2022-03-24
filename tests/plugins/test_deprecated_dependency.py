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

from troubadix.helper.helper import _ROOT
from troubadix.plugin import LinterError
from troubadix.plugins.deprecated_dependency import CheckDeprecatedDependency

from . import PluginTestCase

here = Path.cwd()


class CheckDeprecatedDependencyTestCase(PluginTestCase):
    def setUp(self) -> None:
        self.dir = here / _ROOT / "foo"
        self.dir.mkdir(parents=True)
        self.dep = self.dir / "example.inc"
        self.dep.write_text("script_category(ACT_ATTACK);\n exit(66);")

        return super().setUp()

    def tearDown(self) -> None:
        self.dep.unlink()
        self.dir.rmdir()

    def test_ok(self):
        path = Path(f"{self.dir}/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            "script_category(ACT_ATTACK);"
        )

        results = list(
            CheckDeprecatedDependency.run(
                path,
                content,
            )
        )
        self.assertEqual(len(results), 0)

    def test_no_dependency(self):
        path = Path(f"{self.dir}/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            "script_category(ACT_ATTACK);"
        )

        results = list(
            CheckDeprecatedDependency.run(
                path,
                content,
            )
        )
        self.assertEqual(len(results), 0)

    def test_deprecated(self):
        path = Path(f"{self.dir}/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            "script_category(ACT_ATTACK);\n"
            "exit(66);"
        )

        results = list(
            CheckDeprecatedDependency.run(
                path,
                content,
            )
        )
        self.assertEqual(len(results), 0)

    def test_deprecated2(self):
        path = Path(f"{self.dir}/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            "script_category(ACT_ATTACK);\n"
            'script_tag(name:"deprecated", value:TRUE);'
        )

        results = list(
            CheckDeprecatedDependency.run(
                path,
                content,
            )
        )
        self.assertEqual(len(results), 0)

    def test_dependency_missing(self):
        dependency = "example2.inc"
        path = Path(f"{self.dir}/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar...");\n'
            'script_dependencies("example2.inc");\n'
            "script_category(ACT_SCANNER);"
        )

        results = list(
            CheckDeprecatedDependency.run(
                path,
                content,
            )
        )

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            f"The script dependency {dependency} could "
            "not be found within the VTs.",
            results[0].message,
        )

    def test_deprecated_dependency(self):
        path = Path(f"{self.dir}/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar...");\n'
            'script_dependencies("example.inc");\n'
            "script_category(ACT_SCANNER);"
        )

        results = list(
            CheckDeprecatedDependency.run(
                path,
                content,
            )
        )

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT depends on example.inc, which is marked" "as deprecated.",
            results[0].message,
        )

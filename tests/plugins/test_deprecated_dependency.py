# Copyright (C) 2022 Greenbone AG
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

from troubadix.helper import CURRENT_ENCODING
from troubadix.plugin import LinterError
from troubadix.plugins.deprecated_dependency import CheckDeprecatedDependency

from . import PluginTestCase, TemporaryDirectory


class CheckDeprecatedDependencyTestCase(PluginTestCase):
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.dir = Path(self.tempdir) / "foo"
        self.dir.mkdir(parents=True)
        self.dep = self.dir / "example.nasl"
        self.dep.write_text(
            "  script_category(ACT_ATTACK);\n  exit(66);",
            encoding=CURRENT_ENCODING,
        )

        return super().setUp()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_ok(self):
        path = self.dir / "file.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            "  script_category(ACT_ATTACK);\n"
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckDeprecatedDependency(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_exclude_inc_file(self):
        path = self.dir / "file.inc"
        fake_context = self.create_file_plugin_context(nasl_file=path)
        plugin = CheckDeprecatedDependency(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_no_dependency(self):
        path = self.dir / "file.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            "  script_category(ACT_ATTACK);\n"
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckDeprecatedDependency(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_deprecated(self):
        path = self.dir / "file.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            "  script_category(ACT_ATTACK);\n"
            "exit(66);\n"
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckDeprecatedDependency(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_deprecated2(self):
        path = self.dir / "file.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            "  script_category(ACT_ATTACK);\n"
            '  script_tag(name:"deprecated", value:TRUE);\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckDeprecatedDependency(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_dependency_missing(self):
        dependency = "example2.nasl"
        path = self.dir / "file.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar...");\n'
            '  script_dependencies("example2.nasl");\n'
            "  script_category(ACT_SCANNER);\n"
        )

        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content, root=self.dir
        )
        plugin = CheckDeprecatedDependency(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            f"The script dependency {dependency} could "
            "not be found within the VTs.",
            results[0].message,
        )

    def test_deprecated_dependency(self):
        path = self.dir / "file.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar...");\n'
            '  script_dependencies("example.nasl");\n'
            "  script_category(ACT_SCANNER);\n"
        )

        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content, root=self.dir
        )
        plugin = CheckDeprecatedDependency(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT depends on example.nasl, which is marked as deprecated.",
            results[0].message,
        )

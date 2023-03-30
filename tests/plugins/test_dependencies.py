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

from troubadix.plugin import LinterError, LinterWarning
from troubadix.plugins.dependencies import CheckDependencies

from . import PluginTestCase

here = Path(__file__).parent


class CheckDependenciesTestCase(PluginTestCase):
    def test_ok(self):
        path = here / "file.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content, root=here
        )
        plugin = CheckDependencies(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_exclude_inc_file(self):
        path = here / "file.inc"
        fake_context = self.create_file_plugin_context(nasl_file=path)
        plugin = CheckDependencies(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_dependency_existing(self):
        with self.create_directory() as tmpdir:
            path = tmpdir / "file.nasl"
            example = tmpdir / "common" / "example.inc"
            example.parent.mkdir(parents=True)
            example.touch()
            content = (
                '  script_tag(name:"cvss_base", value:"4.0");\n'
                '  script_tag(name:"summary", value:"Foo Bar...");\n'
                '  script_dependencies("example.inc");\n'
            )
            fake_context = self.create_file_plugin_context(
                nasl_file=path, file_content=content, root=tmpdir
            )
            plugin = CheckDependencies(fake_context)

            results = list(plugin.run())

            self.assertEqual(len(results), 0)

    def test_dependency_missing(self):
        dependency = "example2.inc"
        path = here / "file.nasl"
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar...");\n'
            f'  script_dependencies("{dependency}");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content, root=here
        )
        plugin = CheckDependencies(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            f"The script dependency {dependency} could "
            "not be found within the VTs.",
            results[0].message,
        )

    def test_enterprise_dependency(self):
        with self.create_directory() as tmpdir:
            path = tmpdir / "file.nasl"
            example = tmpdir / "common" / "enterprise" / "example.inc"
            example.parent.mkdir(parents=True)
            example.touch()
            content = (
                '  script_tag(name:"cvss_base", value:"4.0");\n'
                '  script_tag(name:"summary", value:"Foo Bar...");\n'
                '  script_dependencies("enterprise/example.inc");\n'
            )
            fake_context = self.create_file_plugin_context(
                nasl_file=path, file_content=content, root=tmpdir
            )
            plugin = CheckDependencies(fake_context)

            results = list(plugin.run())

            self.assertEqual(len(results), 0)

    def test_policy_warning(self):
        with self.create_directory() as tmpdir:
            path = tmpdir / "file.nasl"
            example = tmpdir / "common" / "Policy" / "example.inc"
            example.parent.mkdir(parents=True)
            example.touch()
            content = (
                '  script_tag(name:"cvss_base", value:"4.0");\n'
                '  script_tag(name:"summary", value:"Foo Bar...");\n'
                '  script_dependencies("Policy/example.inc");\n'
            )
            fake_context = self.create_file_plugin_context(
                nasl_file=path, file_content=content, root=tmpdir
            )
            plugin = CheckDependencies(fake_context)

            results = list(plugin.run())

            self.assertEqual(len(results), 1)

            self.assertIsInstance(results[0], LinterWarning)
            self.assertEqual(
                "The script dependency Policy/example.inc is in a "
                "subdirectory, which might be misplaced.",
                results[0].message,
            )

    def test_error(self):
        with self.create_directory() as tmpdir:
            path = tmpdir / "file.nasl"
            example = tmpdir / "common" / "foo" / "example.inc"
            example.parent.mkdir(parents=True)
            example.touch()
            content = (
                '  script_tag(name:"cvss_base", value:"4.0");\n'
                '  script_tag(name:"summary", value:"Foo Bar...");\n'
                '  script_dependencies("foo/example.inc");\n'
            )
            fake_context = self.create_file_plugin_context(
                nasl_file=path, file_content=content, root=tmpdir
            )
            plugin = CheckDependencies(fake_context)

            results = list(plugin.run())

            self.assertEqual(len(results), 1)

            self.assertIsInstance(results[0], LinterError)
            self.assertEqual(
                "The script dependency foo/example.inc is within a "
                "subdirectory, which is not allowed.",
                results[0].message,
            )

    def test_dependency_missing_newline(self):
        with self.create_directory() as tmpdir:
            path = tmpdir / "file.nasl"
            example = tmpdir / "common" / "example.inc"
            example.parent.mkdir(parents=True)
            example.touch()
            content = (
                '  script_tag(name:"cvss_base", value:"4.0");\n'
                '  script_tag(name:"summary", value:"Foo Bar...");\n'
                '  script_dependencies("example.inc", \n"example2.inc");\n'
            )
            fake_context = self.create_file_plugin_context(
                nasl_file=path, file_content=content, root=tmpdir
            )
            plugin = CheckDependencies(fake_context)

            results = list(plugin.run())

            self.assertEqual(len(results), 1)
            self.assertIsInstance(results[0], LinterError)
            self.assertEqual(
                "The script dependency example2.inc could "
                "not be found within the VTs.",
                results[0].message,
            )

    def test_inline_comment_dependency(self):
        with self.create_directory() as tmpdir:
            path = tmpdir / "file.nasl"
            example = tmpdir / "common" / "example.nasl"
            example2 = tmpdir / "common" / "example2.nasl"
            example.parent.mkdir(parents=True)
            example.touch()
            example2.touch()
            content = (
                '  script_tag(name:"cvss_base", value:"4.0");\n'
                '  script_tag(name:"summary", value:"Foo Bar...");\n'
                '  script_dependencies("example.nasl", #Comment\n'
                '"example2.nasl");\n'
            )
            fake_context = self.create_file_plugin_context(
                nasl_file=path, file_content=content, root=tmpdir
            )
            plugin = CheckDependencies(fake_context)

            results = list(plugin.run())

            self.assertEqual(len(results), 0)

    def test_inline_comment_dependency_nok(self):
        with self.create_directory() as tmpdir:
            path = tmpdir / "file.nasl"
            example = tmpdir / "common" / "example.nasl"
            example.parent.mkdir(parents=True)
            example.touch()
            content = (
                '  script_tag(name:"cvss_base", value:"4.0");\n'
                '  script_tag(name:"summary", value:"Foo Bar...");\n'
                '  script_dependencies("example.nasl", #Comment\n '
                '"example2.nasl");\n'
            )
            fake_context = self.create_file_plugin_context(
                nasl_file=path, file_content=content, root=tmpdir
            )
            plugin = CheckDependencies(fake_context)

            results = list(plugin.run())

            self.assertEqual(len(results), 1)

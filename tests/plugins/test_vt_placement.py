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

from troubadix.plugin import LinterError
from troubadix.plugins.vt_placement import CheckVTPlacement

from . import PluginTestCase


class CheckVTPlacementTestCase(PluginTestCase):
    def test_ok(self):
        with self.create_directory() as tempdir:
            path = tempdir / "file.nasl"
            for _type in ["Product", "Service"]:
                content = (
                    'script_tag(name:"cvss_base", value:"4.0");\n'
                    'script_tag(name:"summary", value:"Foo Bar.");\n'
                    f'script_family("{_type} detection");\n'
                )
                fake_context = self.create_file_plugin_context(
                    nasl_file=path, file_content=content, root=path.parent
                )
                plugin = CheckVTPlacement(fake_context)

                results = list(plugin.run())

                self.assertEqual(len(results), 0)

    def test_exclude_inc_file(self):
        path = Path("some/file.inc")
        fake_context = self.create_file_plugin_context(nasl_file=path)
        plugin = CheckVTPlacement(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_ok_dirs(self):
        with self.create_directory() as tempdir:
            for _dir in ["gsf", "attic"]:
                path = tempdir / _dir / "file.nasl"
                for _type in ["Product", "Service"]:
                    content = (
                        'script_tag(name:"cvss_base", value:"4.0");\n'
                        'script_tag(name:"summary", value:"Foo Bar.");\n'
                        f'script_family("{_type} detection");\n'
                    )
                    fake_context = self.create_file_plugin_context(
                        nasl_file=path, file_content=content, root=tempdir
                    )
                    plugin = CheckVTPlacement(fake_context)

                    results = list(plugin.run())

                    self.assertEqual(len(results), 0)

    def test_ok_deprecated(self):
        with self.create_directory() as tempdir:
            path = tempdir / "file.nasl"
            for _type in ["Product", "Service"]:
                content = (
                    'script_tag(name:"cvss_base", value:"4.0");\n'
                    'script_tag(name:"summary", value:"Foo Bar.");\n'
                    f'script_family("{_type} detection");\n'
                    'script_tag(name:"deprecated", value=TRUE);\n'
                )

                fake_context = self.create_file_plugin_context(
                    nasl_file=path, file_content=content, root=tempdir
                )
                plugin = CheckVTPlacement(fake_context)

                results = list(plugin.run())

                self.assertEqual(len(results), 0)

    def test_no_detection(self):
        with self.create_directory() as tempdir:
            path = tempdir / "file.nasl"
            content = (
                'script_tag(name:"cvss_base", value:"4.0");\n'
                'script_tag(name:"summary", value:"Foo Bar...");\n'
                'script_dependencies("example.inc");\n'
            )

            fake_context = self.create_file_plugin_context(
                nasl_file=path, file_content=content, root=tempdir
            )
            plugin = CheckVTPlacement(fake_context)

            results = list(plugin.run())

            self.assertEqual(len(results), 0)

    def test_wrong_placement(self):
        with self.create_directory() as tempdir:
            path = tempdir / "foo" / "bar" / "file.nasl"
            for _type in ["Product", "Service"]:
                content = (
                    'script_tag(name:"cvss_base", value:"4.0");\n'
                    'script_tag(name:"summary", value:"Foo Bar.");\n'
                    f'script_family("{_type} detection");\n'
                )
                fake_context = self.create_file_plugin_context(
                    nasl_file=path, file_content=content, root=tempdir
                )
                plugin = CheckVTPlacement(fake_context)

                results = list(plugin.run())

                self.assertEqual(len(results), 1)
                self.assertIsInstance(results[0], LinterError)
                self.assertEqual(
                    "VT should be "
                    f"placed in the root directory ({tempdir}).",
                    results[0].message,
                )

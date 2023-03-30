#  Copyright (c) 2022 Greenbone AG
#
#  SPDX-License-Identifier: GPL-3.0-or-later
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

from pathlib import Path

from troubadix.plugins.qod import (
    VALID_QOD_NUM_VALUES,
    VALID_QOD_TYPES,
    CheckQod,
)

from . import PluginTestCase


class CheckQodTestCase(PluginTestCase):
    nasl_file = Path("some/file.nasl")

    def test_ok_qod_num(self):
        content = '  script_tag(name:"qod", value:97);\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.nasl_file, file_content=content
        )
        plugin = CheckQod(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_exclude_inc_file(self):
        path = Path("some/file.inc")
        fake_context = self.create_file_plugin_context(nasl_file=path)
        plugin = CheckQod(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_ok_qod_type(self):
        content = '  script_tag(name:"qod_type", value:"exploit");\n'

        fake_context = self.create_file_plugin_context(
            nasl_file=self.nasl_file, file_content=content
        )
        plugin = CheckQod(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 0)

    def test_missing_qod(self):
        content = '  script_tag(name:"foo", value:"bar");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.nasl_file, file_content=content
        )
        plugin = CheckQod(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertEqual("VT is missing QoD or QoD type", results[0].message)

    def test_too_many_qod(self):
        content = (
            '  script_tag(name:"qod_type", value:"exploit");\n'
            '  script_tag(name:"qod", value:97);\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=self.nasl_file, file_content=content
        )
        plugin = CheckQod(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertEqual("VT contains multiple QoD values", results[0].message)

    def test_wrong_qod_num_str(self):
        content = '  script_tag(name:"qod", value:"foo");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.nasl_file, file_content=content
        )
        plugin = CheckQod(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertEqual(
            'script_tag(name:"qod", value:"foo");: \'foo\' is an invalid QoD'
            " number value. Allowed are"
            f" {', '.join(str(x) for x in VALID_QOD_NUM_VALUES)}",
            results[0].message,
        )

    def test_wrong_qod_num_int(self):
        content = '  script_tag(name:"qod", value:2);\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.nasl_file, file_content=content
        )
        plugin = CheckQod(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertEqual(
            "script_tag(name:\"qod\", value:2);: '2' is an invalid QoD"
            " number value. Allowed are"
            f" {', '.join(str(x) for x in VALID_QOD_NUM_VALUES)}",
            results[0].message,
        )

    def test_wrong_qod_type(self):
        content = '  script_tag(name:"qod_type", value:"foo");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.nasl_file, file_content=content
        )
        plugin = CheckQod(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertEqual(
            'script_tag(name:"qod_type", value:"foo");: \'foo\' is an invalid'
            f" QoD type. Allowed are {', '.join(VALID_QOD_TYPES)}",
            results[0].message,
        )

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
from unittest.mock import MagicMock

from troubadix.plugin import LinterError
from troubadix.plugins.creation_date import CheckCreationDate

from . import PluginTestCase


class CheckCreationDateTestCase(PluginTestCase):
    def test_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"creation_date", value:"2013-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2013)");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckCreationDate(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 0)

    def test_exclude_inc_file(self):
        path = Path("some/file.inc")
        fake_context = self.create_file_plugin_context(nasl_file=path)
        plugin = CheckCreationDate(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_missing(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"cvss_base", value:"7.5");\n'
            'script_tag(name:"cvss_base_vector", '
            'value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckCreationDate(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "No creation date has been found.",
            results[0].message,
        )

    def test_wrong_weekday(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"creation_date", value:"2013-05-14 11:24:55 +0200 '
            '(Mon, 14 May 2013)");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckCreationDate(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "Wrong day of week. Please change it from 'Mon' to 'Tue'.",
            results[0].message,
        )

    def test_no_timezone(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"creation_date", value:"2013-05-14 11:24:55 '
            '(Tue, 14 May 2013)");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckCreationDate(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "False or incorrectly formatted creation_date.",
            results[0].message,
        )

    def test_different_dates(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"creation_date", value:"2013-05-14 11:24:55 +0200 '
            '(Tue, 15 May 2013)");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckCreationDate(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "The creation_date consists of two different dates.",
            results[0].message,
        )

    def test_wrong_length(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"creation_date", value:"2013-05-14 11:24:55 +0200 '
            '(Tue, 14 May 2013 )");'
        )
        fake_context = MagicMock()
        fake_context.nasl_file = path
        fake_context.file_content = content
        plugin = CheckCreationDate(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "False or incorrectly formatted creation_date.",
            results[0].message,
        )

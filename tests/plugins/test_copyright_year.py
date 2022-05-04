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

from troubadix.plugins.copyright_year import CheckCopyrightYear

from . import PluginTestCase


class CheckCopyrightYearTestCase(PluginTestCase):
    def test_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"creation_date", value:"2022-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2013)");',
            'script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");',
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, lines=content
        )
        plugin = CheckCopyrightYear(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 0)

    def test_missing_creation_date(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"qod_type", value:"remote_banner");',
            'script_family("Product detection");',
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, lines=content
        )
        plugin = CheckCopyrightYear(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 1)
        self.assertEqual(
            "Missing creation_date statement in VT", results[0].message
        )

    def test_creation_date_not_copyright_year(self):
        path = Path("some/file.nasl")
        content = (
            'script_tag(name:"creation_date", value:"2022-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2013)");',
            'script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");',
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, lines=content
        )
        plugin = CheckCopyrightYear(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 1)
        self.assertEqual(
            "VT contains a Copyright year not matching "
            "the year 2022 at line 2",
            results[0].message,
        )

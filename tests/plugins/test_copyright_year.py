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

from troubadix.plugins.copyright_year import CheckCopyrightYear

from . import PluginTestCase


class CheckCopyrightYearTestCase(PluginTestCase):
    def test_ok_new_header(self):
        path = Path("some/file.nasl")
        content = (
            "# SPDX-FileCopyrightText: 2022 Greenbone AG",
            '  script_tag(name:"creation_date", value:"2022-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2022)");',
            '  script_copyright("Copyright (C) 2022 Greenbone AG");',
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, lines=content
        )
        plugin = CheckCopyrightYear(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 0)

    def test_ok_old_header(self):
        path = Path("some/file.nasl")
        content = (
            "# Copyright (C) 2022 Greenbone AG",
            '  script_tag(name:"creation_date", value:"2022-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2022)");',
            '  script_copyright("Copyright (C) 2022 Greenbone AG");',
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, lines=content
        )
        plugin = CheckCopyrightYear(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 0)

    def test_exclude_inc_file(self):
        path = Path("some/file.inc")
        fake_context = self.create_file_plugin_context(nasl_file=path)
        plugin = CheckCopyrightYear(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_pre_ok_new_header(self):
        path = Path("some/pre2008/file.nasl")
        content = (
            "# SPDX-FileCopyrightText: 2020 Greenbone AG",
            '  script_tag(name:"creation_date", value:"2022-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2022)");',
            '  script_copyright("Copyright (C) 2020 Greenbone AG");',
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, lines=content
        )
        plugin = CheckCopyrightYear(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 0)

    def test_pre_ok_old_header(self):
        path = Path("some/pre2008/file.nasl")
        content = (
            "# Copyright (C) 2020 Greenbone AG",
            '  script_tag(name:"creation_date", value:"2022-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2022)");',
            '  script_copyright("Copyright (C) 2020 Greenbone AG");',
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, lines=content
        )
        plugin = CheckCopyrightYear(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 0)

    def test_pre_fail(self):
        path = Path("some/pre2008/file.nasl")
        content = (
            '  script_tag(name:"creation_date", value:"2020-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2020)");',
            '  script_copyright("Copyright (C) 2021 Greenbone AG");',
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, lines=content
        )
        plugin = CheckCopyrightYear(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 1)
        self.assertEqual(
            "VT contains a Copyright year not matching "
            "the creation year 2020 at line 2",
            results[0].message,
        )

    def test_missing_creation_date(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"qod_type", value:"remote_banner");',
            '  script_family("Product detection");',
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

    def test_creation_date_not_script_copyright_year(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"creation_date", value:"2022-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2013)");',
            '  script_copyright("Copyright (C) 2020 Greenbone AG");',
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, lines=content
        )
        plugin = CheckCopyrightYear(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 1)
        self.assertEqual(
            "VT contains a Copyright year not matching "
            "the creation year 2022 at line 2",
            results[0].message,
        )

    def test_creation_date_not_old_header_year(self):
        path = Path("some/file.nasl")
        content = (
            "# Copyright (C) 2020 Greenbone AG",
            '  script_tag(name:"creation_date", value:"2022-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2013)");',
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, lines=content
        )
        plugin = CheckCopyrightYear(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 1)
        self.assertEqual(
            "VT contains a Copyright year not matching "
            "the creation year 2022 at line 1",
            results[0].message,
        )

    def test_creation_date_not_new_header_year(self):
        path = Path("some/file.nasl")
        content = (
            "# SPDX-FileCopyrightText: 2020 Greenbone AG",
            '  script_tag(name:"creation_date", value:"2022-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2013)");',
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, lines=content
        )
        plugin = CheckCopyrightYear(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 1)
        self.assertEqual(
            "VT contains a Copyright year not matching "
            "the creation year 2022 at line 1",
            results[0].message,
        )

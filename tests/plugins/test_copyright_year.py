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
            "# SPDX-FileCopyrightText: 2022 Greenbone AG\n"
            "# SPDX-FileCopyrightText: 2022 some other person\n"
            '  script_tag(name:"creation_date", value:"2022-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2022)");\n'
            '  script_copyright("Copyright (C) 2022 Greenbone AG");\n'
        )

        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckCopyrightYear(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 0)

    def test_ok_old_header(self):
        path = Path("some/file.nasl")
        content = (
            "# Copyright (C) 2022 Greenbone AG\n"
            "# Copyright (C) 2022 some other Person\n"
            '  script_tag(name:"creation_date", value:"2022-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2022)");\n'
            '  script_copyright("Copyright (C) 2022 Greenbone AG");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckCopyrightYear(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 0)

    def test_pre2008_ok_new_header(self):
        # tests that special cases pass:
        # copyright < creation year for pre2008
        # additional copyright that is newer but ok
        path = Path("some/pre2008/file.nasl")
        content = (
            "# SPDX-FileCopyrightText: 2010 Greenbone AG\n"
            "# SPDX-FileCopyrightText: New code since 2022 Greenbone AG\n"
            '  script_tag(name:"creation_date", value:"2022-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2022)");\n'
            '  script_copyright("Copyright (C) 2020 Greenbone AG");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckCopyrightYear(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 0)

    def test_pre2008_ok_old_header(self):
        path = Path("some/pre2008/file.nasl")
        content = (
            "# Copyright (C) 2020 Greenbone AG\n"
            '  script_tag(name:"creation_date", value:"2022-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2022)");\n'
            '  script_copyright("Copyright (C) 2020 Greenbone AG");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
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

    def test_missing_creation_date(self):
        path = Path("some/file.nasl")
        content = (
            "# SPDX-FileCopyrightText: 2022 Greenbone AG\n"
            '  script_copyright("Copyright (C) 2022 Greenbone AG");\n'
        )

        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckCopyrightYear(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 1)
        self.assertEqual(
            "Missing creation_date statement in VT", results[0].message
        )

    def test_missing_copyright_tag(self):
        path = Path("some/file.nasl")
        content = (
            "# SPDX-FileCopyrightText: 2022 Greenbone AG\n"
            '  script_tag(name:"creation_date", value:"2022-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2022)");\n'
        )

        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckCopyrightYear(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 1)
        self.assertEqual("Missing copyright tag in VT", results[0].message)

    def test_regex_fail_copyright_tag(self):
        path = Path("some/file.nasl")
        content = (
            "# SPDX-FileCopyrightText: 2022 Greenbone AG\n"
            '  script_tag(name:"creation_date", value:"2022-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2022)");\n'
            '  script_copyright("Copyright (C) Greenbone AG");\n'
        )

        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckCopyrightYear(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 1)
        self.assertEqual(
            "Unable to extract year from script_copyright tag in VT",
            results[0].message,
        )

    def test_missing_header_copyright(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"creation_date", value:"2022-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2022)");\n'
            '  script_copyright("Copyright (C) 2022 Greenbone AG");\n'
        )

        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckCopyrightYear(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 1)
        self.assertEqual(
            "VT header is missing a copyright text",
            results[0].message,
        )
        return

    def test_pre2008_fail(self):
        path = Path("some/pre2008/file.nasl")
        content = (
            "# Copyright (C) 2021 Greenbone AG\n"
            '  script_tag(name:"creation_date", value:"2020-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2020)");\n'
            '  script_copyright("Copyright (C) 2021 Greenbone AG");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckCopyrightYear(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 2)
        self.assertEqual(
            "a pre2008 vt has a copyright tag year newer than the creation_year",
            results[0].message,
        )
        self.assertEqual(
            "a pre2008 vt has a copyright value in the fileheader"
            " newer than the creation_year",
            results[1].message,
        )

    def test_fail(self):
        path = Path("some/file.nasl")
        content = (
            "# SPDX-FileCopyrightText: 3000 Greenbone AG\n"
            '  script_tag(name:"creation_date", value:"2022-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2022)");\n'
            '  script_copyright("Copyright (C) 1000 Greenbone AG");\n'
        )

        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckCopyrightYear(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 2)
        self.assertEqual(
            "script_copyright tag does not match the creation year",
            results[0].message,
        )
        self.assertEqual(
            "a copyright in the fileheader does not match the creation year",
            results[1].message,
        )

# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

from pathlib import Path

from troubadix.plugin import LinterError
from troubadix.plugins.severity_date import CheckSeverityDate

from . import PluginTestCase


class CheckSeverityDateTestCase(PluginTestCase):

    def test_severity_date_ok(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"severity_date", value:"2013-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2013)");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSeverityDate(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 0)

    def test_exclude_inc_file(self):
        path = Path("some/file.inc")
        fake_context = self.create_file_plugin_context(nasl_file=path)
        plugin = CheckSeverityDate(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_missing_severity_date(self):
        path = Path("some/file.nasl")
        content = ""
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSeverityDate(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_severity_date_greater_than_last_modification(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"severity_date", value:"2025-01-01 00:00:01 '
            '+0200 (Wed, 01 Jan 2025)");\n'
            '  script_tag(name:"last_modification", value:"2025-01-01 00:00:00 '
            '+0200 (Wed, 01 Jan 2025)");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSeverityDate(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "The severity_date must not be greater than last_modification date.",
            results[0].message,
        )

    def test_severity_date_equal_last_modification(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"severity_date", value:"2025-01-01 00:00:00 '
            '+0200 (Wed, 01 Jan 2025)");\n'
            '  script_tag(name:"last_modification", value:"2025-01-01 00:00:00 '
            '+0200 (Wed, 01 Jan 2025)");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSeverityDate(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

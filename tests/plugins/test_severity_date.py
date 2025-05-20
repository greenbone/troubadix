# Copyright (C) 2025 Greenbone AG
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path
from unittest.mock import MagicMock

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

    def test_missing(self):
        path = Path("some/file.nasl")
        content = ""
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSeverityDate(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_wrong_weekday(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"severity_date", value:"2013-05-14 11:24:55 '
            '+0200 (Mon, 14 May 2013)");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSeverityDate(fake_context)

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
            '  script_tag(name:"severity_date", value:"2013-05-14 11:24:55 '
            '(Tue, 14 May 2013)");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSeverityDate(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "False or incorrectly formatted severity_date.",
            results[0].message,
        )

    def test_different_dates(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"severity_date", value:"2013-05-14 11:24:55 '
            '+0200 (Tue, 15 May 2013)");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSeverityDate(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "The severity_date consists of two different dates.",
            results[0].message,
        )

    def test_wrong_length(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"severity_date", value:"2013-05-14 11:24:55 '
            '+0200 (Tue, 14 May 2013 )");\n'
        )
        fake_context = MagicMock()
        fake_context.nasl_file = path
        fake_context.file_content = content
        plugin = CheckSeverityDate(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "False or incorrectly formatted severity_date.",
            results[0].message,
        )

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
            "The severity_date must not be greater than the last modification date.",
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

    def test_malformed_hour(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"severity_date", value:"2013-05-14 111:24:55 '
            '+0200 (Tue, 14 May 2013)");\n'
        )
        fake_context = MagicMock()
        fake_context.nasl_file = path
        fake_context.file_content = content
        plugin = CheckSeverityDate(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "False or incorrectly formatted severity_date.",
            results[0].message,
        )

    def test_malformed_second(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"severity_date", value:"2013-05-14 11:24:55s '
            '+0200 (Tue, 14 May 2013)");\n'
        )
        fake_context = MagicMock()
        fake_context.nasl_file = path
        fake_context.file_content = content
        plugin = CheckSeverityDate(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "False or incorrectly formatted severity_date.",
            results[0].message,
        )

    def test_malformed_day(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"severity_date", value:"2013-05-14D 11:24:55 '
            '+0200 (Tue, 14 May 2013)");\n'
        )
        fake_context = MagicMock()
        fake_context.nasl_file = path
        fake_context.file_content = content
        plugin = CheckSeverityDate(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "False or incorrectly formatted severity_date.",
            results[0].message,
        )

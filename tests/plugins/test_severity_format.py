# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

from pathlib import Path

from troubadix.plugin import LinterError
from troubadix.plugins.severity_format import CheckSeverityFormat

from . import PluginTestCase


class CheckSeverityFormatTestCase(PluginTestCase):

    def test_cvss_3_0_vector_ok(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"severity_vector", '
            'value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSeverityFormat(fake_context)

        results = list(plugin.run())

        self.assertEqual(results, [])

    def test_invalid_cvss_3_0_vector(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"severity_vector", '
            'value:"CVSS:3.0/AV:N/AC:N/PR:L/UI:R/S:H/C:H/I:H/A:H");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSeverityFormat(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT has an invalid severity_vector value.",
            results[0].message,
        )

    def test_cvss_3_1_vector_ok(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"severity_vector", '
            'value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSeverityFormat(fake_context)

        results = list(plugin.run())

        self.assertEqual(results, [])

    def test_invalid_cvss_3_1_vector(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"severity_vector", '
            'value:"CVSS:3.1/AV:N/AC:N/PR:L/UI:R/S:H/C:H/I:H/A:H");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSeverityFormat(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT has an invalid severity_vector value.",
            results[0].message,
        )

    def test_cvss_4_0_vector_ok(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"severity_vector", '
            'value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A'
            '/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSeverityFormat(fake_context)

        results = list(plugin.run())

        self.assertEqual(results, [])

    def test_invalid_cvss_4_0_vector(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"severity_vector", '
            'value:"CVSS:4.0/AV:N/AC:N/AT:N/PR:L/UI:N'
            '/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSeverityFormat(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT has an invalid severity_vector value.",
            results[0].message,
        )

    def test_missing_severity_vector(self):
        path = Path("some/file.nasl")
        content = ""
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSeverityFormat(fake_context)

        results = list(plugin.run())

        self.assertEqual(results, [])

    def test_empty_severity_vector(self):
        path = Path("some/file.nasl")
        content = '  script_tag(name:"severity_vector", value:"");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSeverityFormat(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT has an invalid severity_vector value.",
            results[0].message,
        )

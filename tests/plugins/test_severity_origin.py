# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

from pathlib import Path

from troubadix.plugin import LinterError
from troubadix.plugins.severity_origin import CheckSeverityOrigin

from . import PluginTestCase


class CheckSeverityOriginTestCase(PluginTestCase):

    def test_severity_origin_nvd(self):
        path = Path("some/file.nasl")
        content = '  script_tag(name:"severity_origin", value:"NVD");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSeverityOrigin(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_severity_origin_vendor(self):
        path = Path("some/file.nasl")
        content = '  script_tag(name:"severity_origin", value:"Vendor");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSeverityOrigin(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_severity_origin_third_party(self):
        path = Path("some/file.nasl")
        content = '  script_tag(name:"severity_origin", value:"Third Party");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSeverityOrigin(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_severity_origin_greenbone(self):
        path = Path("some/file.nasl")
        content = '  script_tag(name:"severity_origin", value:"Greenbone");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSeverityOrigin(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_severity_origin_other(self):
        path = Path("some/file.nasl")
        content = '  script_tag(name:"severity_origin", value:"Other");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSeverityOrigin(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT has an invalid severity_origin value.",
            results[0].message,
        )

    def test_severity_origin_empty(self):
        path = Path("some/file.nasl")
        content = '  script_tag(name:"severity_origin", value:"");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckSeverityOrigin(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT has an invalid severity_origin value.",
            results[0].message,
        )

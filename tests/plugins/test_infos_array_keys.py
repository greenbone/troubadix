# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG

from pathlib import Path

from troubadix.plugin import LinterError, LinterWarning
from troubadix.plugins.infos_array_keys import CheckInfosArrayKeys

from . import PluginTestCase


class TestInfosArrayKeys(PluginTestCase):
    def test_valid_usage(self):
        content = """
        infos = get_app_version_and_location(cpe: cpe, port: port);
        v = infos["version"];
        if (!infos = get_app_version_and_location()) exit(0);
        l = infos['location'];
        """
        path = Path("test.nasl")
        context = self.create_file_plugin_context(nasl_file=path, file_content=content)
        plugin = CheckInfosArrayKeys(context)
        results = list(plugin.run())
        self.assertEqual(len(results), 0)

    def test_invalid_key_and_naming(self):
        content = """
        info = get_app_version_and_location(cpe: cpe, port: port);
        key = info["bad_key"];
        """
        path = Path("test.nasl")
        context = self.create_file_plugin_context(nasl_file=path, file_content=content)
        plugin = CheckInfosArrayKeys(context)
        results = list(plugin.run())
        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], LinterWarning)
        self.assertIsInstance(results[1], LinterError)
        self.assertIn('Unexpected variable name "info"', results[0].message)
        self.assertIn('Usage of info array with invalid key "bad_key"', results[1].message)

    def test_missing_assignment(self):
        content = "if (get_app_version_and_location()) display('ok');"
        path = Path("test.nasl")
        context = self.create_file_plugin_context(nasl_file=path, file_content=content)
        plugin = CheckInfosArrayKeys(context)
        results = list(plugin.run())
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertIn("Missing assignment", results[0].message)

    def test_comments_and_exclusion(self):
        # Test comments are ignored
        content = """
        # info = get_app_version_and_location();
        infos = get_app_version_and_location();
        """
        path = Path("test.nasl")
        context = self.create_file_plugin_context(nasl_file=path, file_content=content)
        plugin = CheckInfosArrayKeys(context)
        self.assertEqual(len(list(plugin.run())), 0)

        # Test host_details.inc is excluded
        path = Path("host_details.inc")
        context = self.create_file_plugin_context(
            nasl_file=path, file_content="info = get_app_version_and_location();"
        )
        plugin = CheckInfosArrayKeys(context)
        self.assertEqual(len(list(plugin.run())), 0)

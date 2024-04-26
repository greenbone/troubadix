# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG

from pathlib import Path

from tests.plugins import PluginTestCase
from troubadix.plugin import LinterError
from troubadix.plugins.spaces_in_filename import CheckSpacesInFilename


class TestSpacesInFilename(PluginTestCase):
    def test_ok(self):
        nasl_file = Path(__file__).parent / "foo.nasl"
        fake_context = self.create_file_plugin_context(nasl_file=nasl_file)
        plugin = CheckSpacesInFilename(fake_context)
        results = list(plugin.run())
        self.assertEqual(len(results), 0)

    def test_fail(self):
        nasl_file = Path(__file__).parent / "foo bar.nasl"
        fake_context = self.create_file_plugin_context(nasl_file=nasl_file)
        plugin = CheckSpacesInFilename(fake_context)
        results = list(plugin.run())
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            results[0].message,
            f"The VT {nasl_file} contains whitespace in the filename",
        )

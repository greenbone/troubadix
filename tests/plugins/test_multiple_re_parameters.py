# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG

from pathlib import Path

from tests.plugins import PluginTestCase
from troubadix.plugin import LinterError
from troubadix.plugins.multiple_re_parameters import CheckMultipleReParameters


class CheckDuplicateReTestCase(PluginTestCase):
    def test_ok(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_mandatory_keys("foo/bar", re:"foo=1.2.3");\n'
            '#  script_mandatory_keys("foo/bar", re:"foo=1.2.3");\n'
            '  script_mandatory_keys("bar/foo");\n'
            "  line with no script_mandatory_keys pattern\n"
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, lines=content.splitlines()
        )
        plugin = CheckMultipleReParameters(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_fail(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            '  script_mandatory_keys("foo/bar", re:"foo=1.2.3");\n'
            '  script_mandatory_keys("bar/foo", re:"bar=3.2.1");\n'
            '#  script_mandatory_keys("bar/foo", re:"bar=3.2.1");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, lines=content.splitlines()
        )
        plugin = CheckMultipleReParameters(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "The re parameter of script_mandatory_keys can only "
            "be defined once, but was found 2 times",
            results[0].message,
        )

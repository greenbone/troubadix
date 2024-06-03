# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG

from pathlib import Path

from tests.plugins import PluginTestCase
from troubadix.plugin import LinterWarning
from troubadix.plugins.variable_redefinition_in_foreach import (
    CheckVariableRedefinitionInForeach,
)


class CheckVariableRedefinitionInForeachTestCase(PluginTestCase):
    def test_ok(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            'urls = ["foo", "bar"];\n'
            "foreach url(urls) {\n  display(url);\n}\n"
            'url1 = "foo";\n'
            'foreach url(make_list(url1, "bar")) {\n  display(url);\n}'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckVariableRedefinitionInForeach(fake_context)
        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_fail(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = (
            'url1 = "foo";\n'
            "foreach url(url) {\n  display(url);\n}\n"
            "foreach url(make_list(url1, url)) {\n  display(url);\n}\n"
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckVariableRedefinitionInForeach(fake_context)
        results = list(plugin.run())
        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], LinterWarning)
        self.assertEqual(
            "The variable 'url' is redefined "
            "by being the identifier\nand the iterator in the"
            " same foreach loop 'foreach url(url)'",
            results[0].message,
        )
        self.assertEqual(
            "The variable 'url' is used as identifier and\n"
            "as part of the iterator in the"
            " same foreach loop\n'foreach url(make_list(url1, url))'",
            results[1].message,
        )

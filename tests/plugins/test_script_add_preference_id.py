# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG
from pathlib import Path

from troubadix.plugin import LinterError
from troubadix.plugins.script_add_preference_id import (
    CheckScriptAddPreferenceId,
)

from . import PluginTestCase


class CheckScriptAddPreferenceIdTestCase(PluginTestCase):
    def test_unique_ids(self):
        path = Path("some/file.nasl")
        content = """\
script_add_preference(name:"Foo", type:"checkbox", value:"bar", id:1);
script_add_preference(name:"Bar", type:"entry", value:"baz", id:2);
script_add_preference(name:"Baz", type:"radio", value:"qux");
"""
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckScriptAddPreferenceId(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_duplicate_id(self):
        path = Path("some/file.nasl")
        content = """\
script_add_preference(name:"Foo", type:"checkbox", value:"bar", id:1);
script_add_preference(name:"Bar", type:"checkbox", value:"baz", id:1);
"""
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckScriptAddPreferenceId(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "script_add_preference id 1 is used multiple times",
            results[0].message,
        )

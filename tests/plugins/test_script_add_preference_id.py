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
        contents = [
            """
script_add_preference(name:"Bar", type:"entry", value:"baz");
script_add_preference(name:"Baz", type:"radio", value:"qux");
script_add_preference(name:"Foo", type:"radio", value:"bar");
""",
            """
script_add_preference(name:"Bar", type:"entry", value:"baz", id:1);
script_add_preference(name:"Baz", type:"radio", value:"qux");
script_add_preference(name:"Foo", type:"radio", value:"bar", id:3);
""",
            """
script_add_preference(name:"Bar", type:"entry", value:"baz", id:2);
script_add_preference(name:"Baz", type:"radio", value:"qux", id:1);
script_add_preference(name:"Foo", type:"radio", value:"bar", id:3);
""",
            """
script_add_preference(name:"Bar", type:"entry", value:"baz", id:1);
script_add_preference(name:"Baz", type:"radio", value:"qux", id:2);
script_add_preference(name:"Foo", type:"radio", value:"bar", id:3);
""",
        ]

        for content in contents:
            with self.subTest(content=content):
                fake_context = self.create_file_plugin_context(
                    nasl_file=path, file_content=content
                )
                plugin = CheckScriptAddPreferenceId(fake_context)

                results = list(plugin.run())

                self.assertEqual(len(results), 0)

    def test_duplicate_id(self):
        path = Path("some/file.nasl")
        contents = [
            (
                """
script_add_preference(name:"Bar", type:"entry", value:"baz", id:1);
script_add_preference(name:"Baz", type:"radio", value:"qux");
script_add_preference(name:"Foo", type:"radio", value:"bar", id:2);
""",
                "2",
            ),
            (
                """
script_add_preference(name:"Bar", type:"entry", value:"baz");
script_add_preference(name:"Baz", type:"radio", value:"qux", id:1);
script_add_preference(name:"Foo", type:"radio", value:"bar", id:2);
""",
                "1",
            ),
            (
                """
script_add_preference(name:"Bar", type:"entry", value:"baz", id:1);
script_add_preference(name:"Baz", type:"radio", value:"qux", id:3);
script_add_preference(name:"Foo", type:"radio", value:"bar", id:1);
""",
                "1",
            ),
            (
                """
script_add_preference(name:"Bar", type:"entry", value:"baz", id:2);
script_add_preference(name:"Baz", type:"radio", value:"qux", id:1);
script_add_preference(name:"Foo", type:"radio", value:"bar", id:1);
""",
                "1",
            ),
        ]

        for content, expected_id in contents:
            with self.subTest(content=content):
                fake_context = self.create_file_plugin_context(
                    nasl_file=path, file_content=content
                )
                plugin = CheckScriptAddPreferenceId(fake_context)

                results = list(plugin.run())

                self.assertEqual(len(results), 1)
                self.assertIsInstance(results[0], LinterError)
                self.assertEqual(
                    f"script_add_preference id {expected_id} is used multiple times",
                    results[0].message,
                )

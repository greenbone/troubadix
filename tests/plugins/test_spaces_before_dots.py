# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG

from pathlib import Path

from tests.plugins import PluginTestCase
from troubadix.plugins.spaces_before_dots import CheckSpacesBeforeDots


class TestSpacesBeforeDots(PluginTestCase):

    def test_ok(self):
        nasl_file = Path("/some/fake/directory/test.nasl")
        content = """
              script_tag(name:"summary", value:"Foo Bar.");
              script_tag(name:"solution", value:"meh.");
            """
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckSpacesBeforeDots(fake_context)
        results = list(plugin.run())
        self.assertEqual(len(results), 0)

    def test_fail(self):
        nasl_file = Path("/some/fake/directory/test.nasl")
        content = """
              script_tag(name:"summary", value:"Foo Bar .");
              script_tag(name:"vuldetect", value:"Foo Bar .");
              script_tag(name:"insight", value:"Foo Bar .");
              script_tag(name:"impact", value:"Foo Bar .");
              script_tag(name:"affected", value:"Foo Bar .");
              script_tag(name:"solution", value:"meh .");
            """
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckSpacesBeforeDots(fake_context)
        results = list(plugin.run())
        self.assertEqual(len(results), 6)
        self.assertEqual(
            results[0].message,
            "value of script_tag summary has a excess space before the dot:\n"
            " 'script_tag(name:"
            '"summary", value:"Foo Bar .");'
            "'",
        )

    def test_ignore(self):
        nasl_file = Path("/some/fake/directory/test.inc")
        fake_context = self.create_file_plugin_context(nasl_file=nasl_file)
        plugin = CheckSpacesBeforeDots(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

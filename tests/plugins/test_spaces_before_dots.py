# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG

from pathlib import Path

from tests.plugins import PluginTestCase
from troubadix.helper import CURRENT_ENCODING
from troubadix.plugin import LinterFix
from troubadix.plugins.spaces_before_dots import CheckSpacesBeforeDots


class TestSpacesBeforeDots(PluginTestCase):

    def test_ok(self):
        nasl_file = Path("/some/fake/directory/test.nasl")
        content = """
              script_tag(name:"summary", value:"Foo Bar.");
              script_tag(name:"solution", value:"Foo .NET.");
              script_tag(name:"insight", value:"Foo Bar ...");
            """
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckSpacesBeforeDots(fake_context)
        results = list(plugin.run())
        self.assertEqual(len(results), 0)

    def test_fail(self):
        nasl_file = Path("/some/fake/directory/test.nasl")
        content = (
            """
              script_tag(name:"summary", value:"Foo Bar .");
              script_tag(name:"vuldetect", value:"Foo Bar .");
              script_tag(name:"insight", value:"Foo Bar .");
              script_tag(name:"impact", value:"Foo . Bar . Foo");
            """
            'script_tag(name:"affected", value:"Foo\n.\nBar.");'
            'script_tag(name:"solution", value:"Foo Bar\n.");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckSpacesBeforeDots(fake_context)
        results = list(plugin.run())
        self.assertEqual(len(results), 7)
        self.assertEqual(
            results[0].message,
            "value of script_tag summary has at least one occurence of excess"
            " whitespace before a dot:\n"
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

    def test_fix(self):
        with self.create_directory() as tempdir:
            path = tempdir / "file.nasl"
            content = (
                """
                  script_tag(name:"summary", value:"Foo Bar .");
                  script_tag(name:"vuldetect", value:"Foo Bar .");
                  script_tag(name:"insight", value:"Foo .Net Bar .");
                  script_tag(name:"impact", value:"Foo . Bar . Foo");
                """
                'script_tag(name:"affected", value:"Foo\n.\nBar.");'
                'script_tag(name:"solution", value:"Foo Bar\n.");'
            )
            expected_modified_content = (
                """
                  script_tag(name:"summary", value:"Foo Bar.");
                  script_tag(name:"vuldetect", value:"Foo Bar.");
                  script_tag(name:"insight", value:"Foo .Net Bar.");
                  script_tag(name:"impact", value:"Foo. Bar. Foo");
                """
                'script_tag(name:"affected", value:"Foo.\nBar.");'
                'script_tag(name:"solution", value:"Foo Bar.");'
            )
            path.write_text(content, encoding=CURRENT_ENCODING)

            fake_context = self.create_file_plugin_context(
                nasl_file=path, file_content=content
            )

            plugin = CheckSpacesBeforeDots(fake_context)

            # keep list() to consume the iterator
            list(plugin.run())

            results = list(plugin.fix())
            self.assertEqual(len(results), 1)

            self.assertIsInstance(results[0], LinterFix)
            modified_content = path.read_text(encoding=CURRENT_ENCODING)
            self.assertEqual(modified_content, expected_modified_content)

# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

from pathlib import Path

from troubadix.plugins.if_statement_syntax import CheckIfStatementSyntax

from . import PluginTestCase


class CheckIfStatementSyntaxTestCase(PluginTestCase):
    """Test cases for the CheckIfStatementSyntax plugin."""

    def test_valid_if_statements(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = """
        if(condition) {
            display("block statement");
        }

        if(another_condition) display("single statement");

        if(nested_condition) {
            if(inner_condition) {
                display("nested");
            }
        }
        """

        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckIfStatementSyntax(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_unclosed_parenthesis(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = """
        if(unclosed_condition {
            display("this should fail");
        }
        """

        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckIfStatementSyntax(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIn("Unclosed parenthesis", results[0].message)
        self.assertIn("line 2", results[0].message)

    def test_unclosed_brace(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = """
        if(condition) {
            display("missing closing brace");
        # Missing closing brace
        """

        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckIfStatementSyntax(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIn("Unclosed brace", results[0].message)

    def test_missing_statement(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = """
        if(condition)
        # No statement follows
        """

        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckIfStatementSyntax(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIn("Missing statement", results[0].message)

    def test_semicolon_after_condition(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = """
        if(condition);
        {
            display("this will always execute");
        }
        """

        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckIfStatementSyntax(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIn("Semicolon after if condition", results[0].message)

    def test_missing_semicolon_in_expression(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = """
        if(condition) display("missing semicolon")
        # No semicolon at end of expression
        """

        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckIfStatementSyntax(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIn("Missing expression", results[0].message)

    def test_comment_handling(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = """
        # This comment has an unclosed if(condition that should be ignored
        if(real_condition) {
            # Another comment with if(fake
            display("real code");
        }
        """

        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckIfStatementSyntax(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_complex_nested_error(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = """
        if(outer_condition) {
            if(inner_condition {  # Missing closing parenthesis
                display("nested error");
            }
        }
        """

        fake_context = self.create_file_plugin_context(
            nasl_file=nasl_file, file_content=content
        )
        plugin = CheckIfStatementSyntax(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIn("Unclosed parenthesis", results[0].message)

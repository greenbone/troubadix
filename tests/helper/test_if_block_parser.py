# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

import unittest

from troubadix.helper.if_block_parser import find_if_statements


class FindIfStatementsTestCase(unittest.TestCase):
    def test_empty_input(self):
        result = find_if_statements("")
        self.assertEqual(len(result), 0)

    def test_inline_single_expression(self):
        content = 'if(TRUE) display("inline");'
        result = find_if_statements(content)

        self.assertEqual(1, len(result))
        self.assertEqual("TRUE", result[0].condition)
        self.assertEqual('display("inline")', result[0].statement)
        # Check that position is correct (start at 'if', end at semicolon)
        self.assertEqual(0, result[0].if_start)
        self.assertEqual(len(content), result[0].if_end)

    def test_single_line_with_newline(self):
        content = 'if(TRUE)\n  display("single line");'
        result = find_if_statements(content)

        self.assertEqual(1, len(result))
        self.assertEqual("TRUE", result[0].condition)
        self.assertEqual('display("single line")', result[0].statement)

    def test_standard_block(self):
        content = 'if(TRUE) {\n  display("block");\n}'
        result = find_if_statements(content)

        self.assertEqual(1, len(result))
        self.assertEqual("TRUE", result[0].condition)
        self.assertEqual('display("block");', result[0].statement)
        # Check position spans from 'if' to the closing brace
        self.assertEqual(0, result[0].if_start)
        self.assertEqual(len(content), result[0].if_end)

    def test_block_brace_on_newline(self):
        content = 'if(TRUE)\n{\n  display("block");\n}'
        result = find_if_statements(content)

        self.assertEqual(1, len(result))
        self.assertEqual("TRUE", result[0].condition)
        self.assertEqual('display("block");', result[0].statement)

    def test_empty_block(self):
        content = "if(TRUE)\n{\n}"
        result = find_if_statements(content)

        self.assertEqual(1, len(result))
        self.assertEqual("TRUE", result[0].condition)
        self.assertEqual("", result[0].statement.strip())

    def test_compact_block(self):
        content = "if(TRUE){}"
        result = find_if_statements(content)

        self.assertEqual(1, len(result))
        self.assertEqual("TRUE", result[0].condition)
        self.assertEqual("", result[0].statement)

    def test_multiple_if_statements(self):
        content = """
        if(cond1) display("one");
        if(cond2) {
            display("two");
        }
        if(cond3)
            display("three");
        """
        result = find_if_statements(content)
        self.assertEqual(3, len(result))

        self.assertEqual("cond1", result[0].condition)
        self.assertEqual('display("one")', result[0].statement)

        self.assertEqual("cond2", result[1].condition)
        self.assertEqual('display("two");', result[1].statement)

        self.assertEqual("cond3", result[2].condition)
        self.assertEqual('display("three")', result[2].statement)

    def test_nested_if_statements(self):
        content = """
        if(outer) {
            if(inner1) {
                display("nested block");
            }
            if(inner2) display("nested inline");
        }
        """
        result = find_if_statements(content)
        self.assertEqual(3, len(result))

        self.assertEqual("outer", result[0].condition)
        self.assertIn("if(inner1)", result[0].statement)
        self.assertIn("if(inner2)", result[0].statement)

        self.assertEqual("inner1", result[1].condition)
        self.assertIn('display("nested block")', result[1].statement)

        self.assertEqual("inner2", result[2].condition)
        self.assertEqual('display("nested inline")', result[2].statement)

    def test_complex_condition(self):
        content = (
            'if (a == 1 && b > 2 || c != "string") { display("complex"); }'
        )
        result = find_if_statements(content)

        self.assertEqual(1, len(result))
        self.assertEqual(
            'a == 1 && b > 2 || c != "string"', result[0].condition
        )
        self.assertEqual('display("complex");', result[0].statement)

    def test_if_with_problematic_stuff(self):
        # escape single quote and backslash, function call in condition
        content = r"if(some_func('\'\\')) display('\'test\\');"
        result = find_if_statements(content)

        self.assertEqual(1, len(result))
        self.assertEqual(r"some_func('\'\\')", result[0].condition)
        self.assertEqual(r"display('\'test\\')", result[0].statement)

    def test_unclosed_parenthesis(self):
        content = "if(unclosed condition\ndisplay();"
        with self.assertRaises(ValueError) as cm:
            find_if_statements(content)
        self.assertEqual(
            "Unclosed parenthesis in if statement at line 1",
            str(cm.exception),
        )

    def test_no_statement_after_condition(self):
        content = "if(condition)"
        with self.assertRaises(ValueError) as cm:
            find_if_statements(content)
        self.assertEqual(
            "Missing statement after if condition at line 1",
            str(cm.exception),
        )

    def test_useless_semicolon(self):
        content = "if(condition);"
        with self.assertRaises(ValueError) as cm:
            find_if_statements(content)
        self.assertEqual(
            "Semicolon after if condition at line 1 makes following block always execute."
            " Remove semicolon to fix.",
            str(cm.exception),
        )

    def test_unclosed_block_brace(self):
        content = "if(condition) {\ndisplay();\n# Missing closing brace"
        with self.assertRaises(ValueError) as cm:
            find_if_statements(content)
        self.assertEqual(
            "Unclosed brace in if statement at line 1",
            str(cm.exception),
        )

    def test_no_semicolon_in_single_expression(self):
        content = "if(condition) display()"  # Missing semicolon
        with self.assertRaises(ValueError) as cm:
            find_if_statements(content)
        self.assertEqual(
            "Missing expression after if condition at line 1",
            str(cm.exception),
        )

    def test_complex_condition_with_unmatched_brace(self):
        content = "if(func(1, 2) || check(a) { display(); }"  # Missing closing ) in condition
        with self.assertRaises(ValueError) as cm:
            find_if_statements(content)
        self.assertEqual(
            "Unclosed parenthesis in if statement at line 1",
            str(cm.exception),
        )

    def test_position_info_in_error_message(self):
        content = "# Some comment\nif(bad) something"  # No semicolon
        with self.assertRaises(ValueError) as cm:
            find_if_statements(content)
        error_msg = str(cm.exception)
        self.assertIn("at line 2", error_msg)

    def test_condition_and_statement_positions_block(self):
        content = 'if(TRUE) {\n  display("block");\n}'
        result = find_if_statements(content)

        self.assertEqual(1, len(result))
        # Check condition position (inside parentheses)
        self.assertEqual(3, result[0].condition_start)
        self.assertEqual(7, result[0].condition_end)
        # Check statement position (inside braces)
        self.assertEqual(10, result[0].statement_start)
        self.assertEqual(31, result[0].statement_end)

    def test_condition_and_statement_positions_single(self):
        content = 'if(num > 5) display("inline");'
        result = find_if_statements(content)

        self.assertEqual(1, len(result))
        # Check condition position (inside parentheses)
        self.assertEqual(3, result[0].condition_start)
        self.assertEqual(10, result[0].condition_end)
        # Check statement position (after parenthesis to semicolon)
        self.assertEqual(12, result[0].statement_start)
        self.assertEqual(29, result[0].statement_end)

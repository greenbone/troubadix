# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

import unittest

from troubadix.helper.if_block_parser import IfErrorType, find_if_statements


class FindIfStatementsTestCase(unittest.TestCase):
    def test_empty_input(self):
        result = find_if_statements("")
        self.assertEqual(len(result.statements), 0)
        self.assertEqual(len(result.errors), 0)

    def test_inline_single_expression(self):
        content = 'if(TRUE) display("inline");'
        result = find_if_statements(content)

        self.assertEqual(1, len(result.statements))
        self.assertEqual("TRUE", result.statements[0].condition)
        self.assertEqual('display("inline")', result.statements[0].outcome)
        # Check that position is correct (start at 'if', end at semicolon)
        self.assertEqual(0, result.statements[0].if_start)
        self.assertEqual(len(content), result.statements[0].if_end)

    def test_single_line_with_newline(self):
        content = 'if(TRUE)\n  display("single line");'
        result = find_if_statements(content)

        self.assertEqual(1, len(result.statements))
        self.assertEqual("TRUE", result.statements[0].condition)
        self.assertEqual('display("single line")', result.statements[0].outcome)

    def test_standard_block(self):
        content = 'if(TRUE) {\n  display("block");\n}'
        result = find_if_statements(content)

        self.assertEqual(1, len(result.statements))
        self.assertEqual("TRUE", result.statements[0].condition)
        self.assertEqual('display("block");', result.statements[0].outcome)
        # Check position spans from 'if' to the closing brace
        self.assertEqual(0, result.statements[0].if_start)
        self.assertEqual(len(content), result.statements[0].if_end)

    def test_block_brace_on_newline(self):
        content = 'if(TRUE)\n{\n  display("block");\n}'
        result = find_if_statements(content)

        self.assertEqual(1, len(result.statements))
        self.assertEqual("TRUE", result.statements[0].condition)
        self.assertEqual('display("block");', result.statements[0].outcome)

    def test_empty_block(self):
        content = "if(TRUE)\n{\n}"
        result = find_if_statements(content)

        self.assertEqual(1, len(result.statements))
        self.assertEqual("TRUE", result.statements[0].condition)
        self.assertEqual("", result.statements[0].outcome)

    def test_compact_block(self):
        content = "if(TRUE){}"
        result = find_if_statements(content)

        self.assertEqual(1, len(result.statements))
        self.assertEqual("TRUE", result.statements[0].condition)
        self.assertEqual("", result.statements[0].outcome)

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
        self.assertEqual(3, len(result.statements))

        self.assertEqual("cond1", result.statements[0].condition)
        self.assertEqual('display("one")', result.statements[0].outcome)

        self.assertEqual("cond2", result.statements[1].condition)
        self.assertEqual('display("two");', result.statements[1].outcome)

        self.assertEqual("cond3", result.statements[2].condition)
        self.assertEqual('display("three")', result.statements[2].outcome)

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
        self.assertEqual(3, len(result.statements))

        self.assertEqual("outer", result.statements[0].condition)
        self.assertIn("if(inner1)", result.statements[0].outcome)
        self.assertIn("if(inner2)", result.statements[0].outcome)

        self.assertEqual("inner1", result.statements[1].condition)
        self.assertIn('display("nested block")', result.statements[1].outcome)

        self.assertEqual("inner2", result.statements[2].condition)
        self.assertEqual(
            'display("nested inline")', result.statements[2].outcome
        )

    def test_complex_condition(self):
        content = (
            'if (a == 1 && b > 2 || c != "string") { display("complex"); }'
        )
        result = find_if_statements(content)

        self.assertEqual(1, len(result.statements))
        self.assertEqual(
            'a == 1 && b > 2 || c != "string"', result.statements[0].condition
        )
        self.assertEqual('display("complex");', result.statements[0].outcome)

    def test_if_with_problematic_stuff(self):
        # escape single quote and backslash, function call in condition
        content = r"if(some_func('\'\\')) display('\'test\\');"
        result = find_if_statements(content)

        self.assertEqual(1, len(result.statements))
        self.assertEqual(r"some_func('\'\\')", result.statements[0].condition)
        self.assertEqual(r"display('\'test\\')", result.statements[0].outcome)

    def test_unclosed_parenthesis(self):
        content = "if(unclosed condition\ndisplay();"
        result = find_if_statements(content)
        self.assertEqual(len(result.statements), 0)
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.errors[0].error_type.name, "UNCLOSED_CONDITION")

    def test_no_statement_after_condition(self):
        content = "if(condition)"
        result = find_if_statements(content)
        self.assertEqual(len(result.statements), 0)
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.errors[0].error_type.name, "MISSING_OUTCOME")

    def test_useless_semicolon(self):
        content = "if(condition);"
        result = find_if_statements(content)
        self.assertEqual(len(result.statements), 0)
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(
            result.errors[0].error_type.name, "TERMINATED_AFTER_CONDITION"
        )

    def test_unclosed_block_brace(self):
        content = "if(condition) {\ndisplay();\n# Missing closing brace"
        result = find_if_statements(content)
        self.assertEqual(len(result.statements), 0)
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.errors[0].error_type.name, "UNCLOSED_BODY")

    def test_no_semicolon_in_single_expression(self):
        content = "if(condition) display()"  # Missing semicolon
        result = find_if_statements(content)
        self.assertEqual(len(result.statements), 0)
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.errors[0].error_type.name, "MISSING_STATEMENT")

    def test_complex_condition_with_unmatched_brace(self):
        content = "if(func(1, 2) || check(a) { display(); }"  # Missing closing ) in condition
        result = find_if_statements(content)
        self.assertEqual(len(result.statements), 0)
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.errors[0].error_type.name, "UNCLOSED_CONDITION")

    def test_position_info_in_error_message(self):
        content = "# Some comment\nif(bad) something"  # No semicolon
        result = find_if_statements(content)
        self.assertEqual(len(result.statements), 0)
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.errors[0].line, 2)

    def test_condition_and_statement_positions_block(self):
        content = 'if(TRUE) {\n  display("block");\n}'
        result = find_if_statements(content)

        self.assertEqual(1, len(result.statements))
        # Check condition position (inside parentheses)
        self.assertEqual(3, result.statements[0].condition_start)
        self.assertEqual(7, result.statements[0].condition_end)
        # Check outcome position (inside braces)
        self.assertEqual(10, result.statements[0].outcome_start)
        self.assertEqual(31, result.statements[0].outcome_end)

    def test_condition_and_statement_positions_single(self):
        content = 'if(num > 5) display("inline");'
        result = find_if_statements(content)

        self.assertEqual(1, len(result.statements))
        # Check condition position (inside parentheses)
        self.assertEqual(3, result.statements[0].condition_start)
        self.assertEqual(10, result.statements[0].condition_end)
        # Check outcome position (after parenthesis to semicolon)
        self.assertEqual(12, result.statements[0].outcome_start)
        self.assertEqual(29, result.statements[0].outcome_end)

    def test_mixed_valid_and_invalid_if_statements(self):
        content = """
        if(a > 0) display("ok1");
        if(b > 0) ;
        if(c > 0) {
            display("ok2");
        }
        if(d > 0)
            if(e > 0) display("ok3");
        if(f > 0 display();
        """
        result = find_if_statements(content)
        self.assertEqual(4, len(result.statements))
        self.assertEqual(2, len(result.errors))
        self.assertEqual("a > 0", result.statements[0].condition)
        self.assertEqual(
            IfErrorType.TERMINATED_AFTER_CONDITION,
            result.errors[0].error_type,
        )
        self.assertEqual(
            IfErrorType.UNCLOSED_CONDITION, result.errors[1].error_type
        )

    def test_multiple_nested_inline_if_statements(self):
        content = """
if(a > 0)

    if(b > 0)

        if(c > 0)

            display("deep");
        """
        result = find_if_statements(content)
        # Should parse 3 nested if statements
        self.assertEqual(3, len(result.statements))
        self.assertEqual("a > 0", result.statements[0].condition)
        self.assertIn("if(b > 0)", result.statements[0].outcome)
        self.assertEqual("b > 0", result.statements[1].condition)
        self.assertIn("if(c > 0)", result.statements[1].outcome)
        self.assertEqual("c > 0", result.statements[2].condition)
        self.assertEqual('display("deep")', result.statements[2].outcome)

import unittest

from troubadix.helper.if_block_parser import find_if_statements


class FindIfStatementsTestCase(unittest.TestCase):
    def test_empty_input(self):
        result = find_if_statements("")
        self.assertEqual(len(result), 0)

    def test_inline_single_expression(self):
        content = 'if(TRUE) display("inline");'
        result = find_if_statements(content)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].condition, "TRUE")
        self.assertEqual(result[0].statement, 'display("inline")')
        # Check that position is correct (start at 'if', end at semicolon)
        self.assertEqual(result[0].position[0], 0)
        self.assertEqual(result[0].position[1], len(content) - 1)

    def test_single_line_with_newline(self):
        content = 'if(TRUE)\n  display("single line");'
        result = find_if_statements(content)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].condition, "TRUE")
        self.assertEqual(result[0].statement, 'display("single line")')

    def test_standard_block(self):
        content = 'if(TRUE) {\n  display("block");\n}'
        result = find_if_statements(content)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].condition, "TRUE")
        self.assertTrue('display("block")' in result[0].statement)
        # Check position spans from 'if' to the closing brace
        self.assertEqual(result[0].position[0], 0)
        self.assertEqual(result[0].position[1], len(content) - 1)

    def test_block_brace_on_newline(self):
        content = 'if(TRUE)\n{\n  display("block");\n}'
        result = find_if_statements(content)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].condition, "TRUE")
        self.assertTrue('display("block")' in result[0].statement)

    def test_empty_block(self):
        content = "if(TRUE)\n{\n}"
        result = find_if_statements(content)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].condition, "TRUE")
        self.assertEqual(result[0].statement.strip(), "")

    def test_compact_block(self):
        content = "if(TRUE){}"
        result = find_if_statements(content)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].condition, "TRUE")
        self.assertEqual(result[0].statement, "")

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
        self.assertEqual(len(result), 3)

        self.assertEqual(result[0].condition, "cond1")
        self.assertEqual(result[0].statement, 'display("one")')

        self.assertEqual(result[1].condition, "cond2")
        self.assertTrue('display("two")' in result[1].statement)

        self.assertEqual(result[2].condition, "cond3")
        self.assertEqual(result[2].statement, 'display("three")')

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
        self.assertEqual(len(result), 3)

        self.assertEqual(result[0].condition, "outer")
        self.assertTrue("if(inner1)" in result[0].statement)
        self.assertTrue("if(inner2)" in result[0].statement)

        self.assertEqual(result[1].condition, "inner1")
        self.assertTrue('display("nested block")' in result[1].statement)

        self.assertEqual(result[2].condition, "inner2")
        self.assertEqual(result[2].statement, 'display("nested inline")')

    def test_complex_condition(self):
        content = (
            'if (a == 1 && b > 2 || c != "string") { display("complex"); }'
        )
        result = find_if_statements(content)

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0].condition, 'a == 1 && b > 2 || c != "string"'
        )
        self.assertTrue('display("complex")' in result[0].statement)

    def test_if_with_problematic_stuff(self):
        # escape single quote and backslash, function call incondition
        content = r"if(some_func('\'\\')) display('\'test\\');"
        result = find_if_statements(content)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].condition, r"some_func('\'\\')")
        self.assertEqual(result[0].statement, r"display('\'test\\')")

    def test_unclosed_parenthesis(self):
        content = "if(unclosed condition\ndisplay();"
        with self.assertRaises(ValueError) as cm:
            find_if_statements(content)
        self.assertIn("Unclosed ( in if statement", str(cm.exception))

    def test_no_statement_after_condition(self):
        content = "if(condition)"
        with self.assertRaises(ValueError) as cm:
            find_if_statements(content)
        self.assertIn(
            "No statement found after if condition", str(cm.exception)
        )

    def test_useless_semicolon(self):
        content = "if(condition);"
        with self.assertRaises(ValueError) as cm:
            find_if_statements(content)
        self.assertIn(
            "Useless if statement with immediate semicolon", str(cm.exception)
        )

    def test_unclosed_block_brace(self):
        content = "if(condition) {\ndisplay();\n# Missing closing brace"
        with self.assertRaises(ValueError) as cm:
            find_if_statements(content)
        self.assertIn(
            "Error finding block end for if statement", str(cm.exception)
        )
        self.assertIn("Unclosed { in if statement", str(cm.exception))

    def test_no_semicolon_in_single_expression(self):
        content = "if(condition) display()"  # Missing semicolon
        with self.assertRaises(ValueError) as cm:
            find_if_statements(content)
        self.assertIn(
            "No valid expression found after if condition", str(cm.exception)
        )

    def test_complex_condition_with_unmatched_brace(self):
        content = "if(func(1, 2) || check(a) { display(); }"  # Missing closing ) in condition
        with self.assertRaises(ValueError) as cm:
            find_if_statements(content)
        self.assertIn("Error in if statement", str(cm.exception))

    def test_position_info_in_error_message(self):
        content = "# Some comment\nif(bad) something"  # No semicolon
        with self.assertRaises(ValueError) as cm:
            find_if_statements(content)
        error_msg = str(cm.exception)
        self.assertIn("in line 2 at position 1", error_msg)

    def test_condition_and_statement_positions_block(self):
        content = 'if(TRUE) {\n  display("block");\n}'
        result = find_if_statements(content)

        self.assertEqual(len(result), 1)
        # Check condition position (inside parentheses)
        self.assertEqual(result[0].condition_position, (3, 7))
        # Check statement position (inside braces)
        self.assertEqual(result[0].statement_position, (10, 31))

    def test_condition_and_statement_positions_single(self):
        content = 'if(num > 5) display("inline");'
        result = find_if_statements(content)

        self.assertEqual(len(result), 1)
        # Check condition position (inside parentheses)
        self.assertEqual(result[0].condition_position, (3, 10))
        # Check statement position (after parenthesis to semicolon)
        self.assertEqual(result[0].statement_position, (12, 29))


if __name__ == "__main__":
    unittest.main()

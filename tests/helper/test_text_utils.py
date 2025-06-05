"""Unit tests for parsing utility functions."""

import unittest

from troubadix.helper.text_utils import (
    build_line_starts,
    handle_string_context,
    index_to_linecol,
    is_position_in_string,
)


class TestHandleStringContext(unittest.TestCase):
    def test_not_in_quotes(self):
        escape_next, in_double, in_single = handle_string_context(
            "a", False, False, False
        )
        self.assertEqual(
            (escape_next, in_double, in_single), (False, False, False)
        )

    def test_enter_double_quotes(self):
        escape_next, in_double, in_single = handle_string_context(
            '"', False, False, False
        )
        self.assertEqual(
            (escape_next, in_double, in_single), (False, True, False)
        )

    def test_exit_double_quotes(self):
        escape_next, in_double, in_single = handle_string_context(
            '"', False, True, False
        )
        self.assertEqual(
            (escape_next, in_double, in_single), (False, False, False)
        )

    def test_enter_single_quotes(self):
        escape_next, in_double, in_single = handle_string_context(
            "'", False, False, False
        )
        self.assertEqual(
            (escape_next, in_double, in_single), (False, False, True)
        )

    def test_exit_single_quotes(self):
        escape_next, in_double, in_single = handle_string_context(
            "'", False, False, True
        )
        self.assertEqual(
            (escape_next, in_double, in_single), (False, False, False)
        )

    def test_escape_in_single_quotes(self):
        escape_next, in_double, in_single = handle_string_context(
            "\\", False, False, True
        )
        self.assertEqual(
            (escape_next, in_double, in_single), (True, False, True)
        )

    def test_escaped_single_quote_in_single_quotes(self):
        escape_next, in_double, in_single = handle_string_context(
            "'", True, False, True
        )
        self.assertEqual(
            (escape_next, in_double, in_single), (False, False, True)
        )

    def test_ignore_single_quotes_in_double_quotes(self):
        escape_next, in_double, in_single = handle_string_context(
            "'", False, True, False
        )
        self.assertEqual(
            (escape_next, in_double, in_single), (False, True, False)
        )

    def test_ignore_double_quotes_in_single_quotes(self):
        escape_next, in_double, in_single = handle_string_context(
            '"', False, False, True
        )
        self.assertEqual(
            (escape_next, in_double, in_single), (False, False, True)
        )

    def test_nasl_backslash_string_sequence(self):
        # Test the sequence "\" in NASL - a valid string where escaping is ignored
        # The char \ inside a double quote should not escape the next char because
        # in double quotes, the backslash either is a parse error if not the last char
        # or treated as literal character.
        # For keeping string context only escaped single quotes are problematic.
        escape_next, in_double, in_single = False, False, False
        escape_next, in_double, in_single = handle_string_context(
            '"', escape_next, in_double, in_single
        )
        self.assertEqual(
            (escape_next, in_double, in_single), (False, True, False)
        )
        escape_next, in_double, in_single = handle_string_context(
            "\\", escape_next, in_double, in_single
        )
        self.assertEqual(
            (escape_next, in_double, in_single), (False, True, False)
        )
        escape_next, in_double, in_single = handle_string_context(
            '"', escape_next, in_double, in_single
        )
        self.assertEqual(
            (escape_next, in_double, in_single), (False, False, False)
        )


class TestBuildLineStarts(unittest.TestCase):
    def test_empty_string(self):
        starts = build_line_starts("")
        self.assertEqual(starts, [0])

    def test_multiple_lines(self):
        starts = build_line_starts("line1\nline2\nline3\n")
        self.assertEqual(starts, [0, 6, 12, 18])

    def test_empty_lines(self):
        starts = build_line_starts("\n\n\n")
        self.assertEqual(starts, [0, 1, 2, 3])

    def test_trailing_newline(self):
        starts = build_line_starts("hello\n")
        self.assertEqual(starts, [0, 6])


class TestIndexToLinecol(unittest.TestCase):
    def test_start_of_file(self):
        line, col = index_to_linecol("hello\nworld", 0)
        self.assertEqual((line, col), (1, 1))

    def test_middle_of_first_line(self):
        line, col = index_to_linecol("hello\nworld", 2)
        self.assertEqual((line, col), (1, 3))

    def test_end_of_first_line(self):
        line, col = index_to_linecol("hello\nworld", 5)
        self.assertEqual((line, col), (1, 6))

    def test_start_of_second_line(self):
        line, col = index_to_linecol("hello\nworld", 6)
        self.assertEqual((line, col), (2, 1))

    def test_end_of_file(self):
        line, col = index_to_linecol("hello\nworld", 11)
        self.assertEqual((line, col), (2, 6))

    def test_multiline_file(self):
        text = "line1\nline2\nline3"
        line, col = index_to_linecol(text, 10)
        self.assertEqual((line, col), (2, 5))

    def test_with_precomputed_line_starts(self):
        text = "line1\nline2\nline3"
        line_starts = build_line_starts(text)
        line, col = index_to_linecol(text, 10, line_starts)
        self.assertEqual((line, col), (2, 5))

    def test_empty_file(self):
        line, col = index_to_linecol("", 0)
        self.assertEqual((line, col), (1, 1))


class TestIsPositionInString(unittest.TestCase):
    def test_no_strings(self):
        text = "x = 5; y = 10;"
        self.assertFalse(is_position_in_string(text, 0))
        self.assertFalse(is_position_in_string(text, 7))

    def test_position_before_string(self):
        text = 'x = "hello";'
        self.assertFalse(is_position_in_string(text, 0))
        self.assertFalse(is_position_in_string(text, 3))

    def test_position_inside_double_quote_string(self):
        text = 'x = "hello";'
        self.assertTrue(is_position_in_string(text, 5))  # inside "hello"
        self.assertTrue(is_position_in_string(text, 9))  # inside "hello"

    def test_position_inside_single_quote_string(self):
        text = "x = 'world';"
        self.assertTrue(is_position_in_string(text, 5))  # inside 'world'
        self.assertTrue(is_position_in_string(text, 9))  # inside 'world'

    def test_position_after_string(self):
        text = 'x = "hello";'
        self.assertFalse(is_position_in_string(text, 11))  # after string

    def test_escaped_quote_in_single_quotes(self):
        text = "x = 'don\\'t';"
        self.assertTrue(is_position_in_string(text, 8))  # inside the string
        self.assertTrue(
            is_position_in_string(text, 10)
        )  # after the escaped quote

    def test_mixed_quotes(self):
        text = 'a = "it\'s ok"; b = \'say "hi"\';'
        self.assertTrue(is_position_in_string(text, 6))  # inside "it's ok"
        self.assertTrue(is_position_in_string(text, 22))  # inside 'say "hi"'
        self.assertFalse(is_position_in_string(text, 15))  # between strings

    def test_position_at_quote_characters(self):
        # This checks that the implementation considers only characters before the current index,
        # so the opening quote is not inside the string,
        # but the closing quote is still considered inside.
        text = 'x = "hello";'
        self.assertFalse(is_position_in_string(text, 4))  # at opening quote
        self.assertTrue(is_position_in_string(text, 10))  # at closing quote


if __name__ == "__main__":
    unittest.main()

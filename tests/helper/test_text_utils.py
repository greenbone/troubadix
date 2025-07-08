# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

import unittest

from troubadix.helper.text_utils import (
    StringState,
    index_to_linecol,
    is_position_in_string,
)


class TestStringState(unittest.TestCase):
    def test_process_normal_char_outside_strings(self):
        state = StringState()
        state.process_next_char("a")
        self.assertFalse(state.escape_next)
        self.assertFalse(state.in_string)

    def test_enter_double_quotes(self):
        state = StringState()
        state.process_next_char('"')
        self.assertFalse(state.escape_next)
        self.assertTrue(state.in_double_quote)
        self.assertTrue(state.in_string)

    def test_exit_double_quotes(self):
        state = StringState(in_double_quote=True)
        state.process_next_char('"')
        self.assertFalse(state.escape_next)
        self.assertFalse(state.in_string)

    def test_enter_single_quotes(self):
        state = StringState()
        state.process_next_char("'")
        self.assertFalse(state.escape_next)
        self.assertTrue(state.in_single_quote)
        self.assertTrue(state.in_string)

    def test_exit_single_quotes(self):
        state = StringState(in_single_quote=True)
        state.process_next_char("'")
        self.assertFalse(state.escape_next)
        self.assertFalse(state.in_string)

    def test_escape_in_single_quotes(self):
        state = StringState(in_single_quote=True)
        state.process_next_char("\\")
        self.assertTrue(state.escape_next)
        self.assertTrue(state.in_single_quote)
        self.assertTrue(state.in_string)

    def test_escaped_single_quote_in_single_quotes(self):
        state = StringState(escape_next=True, in_single_quote=True)
        state.process_next_char("'")
        self.assertFalse(state.escape_next)
        self.assertTrue(state.in_single_quote)
        self.assertTrue(state.in_string)

    def test_ignore_single_quotes_in_double_quotes(self):
        state = StringState(in_double_quote=True)
        state.process_next_char("'")
        self.assertFalse(state.escape_next)
        self.assertTrue(state.in_double_quote)
        self.assertTrue(state.in_string)

    def test_ignore_double_quotes_in_single_quotes(self):
        state = StringState(in_single_quote=True)
        state.process_next_char('"')
        self.assertFalse(state.escape_next)
        self.assertTrue(state.in_single_quote)
        self.assertTrue(state.in_string)

    def test_nasl_backslash_string_sequence(self):
        # Test the sequence "\" in NASL - a valid string where escaping is ignored
        state = StringState()

        # Enter double quote
        state.process_next_char('"')
        self.assertFalse(state.escape_next)
        self.assertTrue(state.in_double_quote)

        # Process backslash in double quotes (should not set escape flag)
        state.process_next_char("\\")
        self.assertFalse(state.escape_next)
        self.assertTrue(state.in_double_quote)

        # Exit double quote
        state.process_next_char('"')
        self.assertFalse(state.escape_next)
        self.assertFalse(state.in_string)


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
        line, col = index_to_linecol("hello\nworld", 10)
        self.assertEqual((line, col), (2, 5))

    def test_multiline_file(self):
        text = "line1\nline2\nline3"
        line, col = index_to_linecol(text, 10)
        self.assertEqual((line, col), (2, 5))

    def test_empty_file(self):
        self.assertRaises(ValueError, index_to_linecol, "", 0)


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

# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

import unittest

from troubadix.helper.remove_comments import remove_comments


class RemoveCommentsTestCase(unittest.TestCase):
    def test_empty_string(self):
        input_content = ""
        expected_output = ""
        self.assertEqual(remove_comments(input_content), expected_output)

    def test_no_comments(self):
        input_content = (
            "function detect_archlinux(sock, port, SCRIPT_DESC, is_pfsense) {"
        )
        expected_output = input_content
        self.assertEqual(remove_comments(input_content), expected_output)

    def test_full_line_comments(self):
        input_content = "# comment\nfunction hello() {\n    # Another comment\n    return 42;"
        expected_output = "\nfunction hello() {\n\n    return 42;"
        self.assertEqual(remove_comments(input_content), expected_output)

    def test_inline_comments(self):
        input_content = (
            "function hello(){ # A function\n    return 42; # The answer"
        )
        expected_output = "function hello(){ \n    return 42; "
        self.assertEqual(remove_comments(input_content), expected_output)

    def test_hash_in_strings(self):
        input_content = "message = 'This # is not a comment';\nurl = \"http://example.com/#anchor\";"
        expected_output = input_content
        self.assertEqual(remove_comments(input_content), expected_output)

    def test_mixed_quotes_and_comments(self):
        input_content = (
            "display('Hash: #'); # Real comment\n"
            's = "My string with # character"; # Another comment'
        )
        expected_output = (
            "display('Hash: #'); \ns = \"My string with # character\"; "
        )
        self.assertEqual(remove_comments(input_content), expected_output)

    def test_complex_scenario(self):
        # ruff does not allow whitespace at end of lines so this looks a bit weird
        input_content = """function hello(){
    # Comment at start
    if (TRUE) {# inline comment
        display('Hello # not a comment');
    # Full comment line
        display("Hash: #");# end comment
    }
}"""

        expected_output = """function hello(){

    if (TRUE) {
        display('Hello # not a comment');

        display("Hash: #");
    }
}"""

        self.assertEqual(remove_comments(input_content), expected_output)

    def test_indented_comments(self):
        input_content = (
            "function func() {\n    # Indented comment\n    return 0;\n}"
        )
        expected_output = "function func() {\n\n    return 0;\n}"
        self.assertEqual(remove_comments(input_content), expected_output)

    def test_backslash_double_quotes(self):
        input_content = r'display("\"); # This is a comment'
        expected_output = r'display("\"); '
        self.assertEqual(remove_comments(input_content), expected_output)

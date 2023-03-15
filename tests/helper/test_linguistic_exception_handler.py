# Copyright (C) 2022 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import unittest

from troubadix.helper.linguistic_exception_handler import (
    CompositeCheck,
    FileCheck,
    FilePatternCheck,
    FilesCheck,
    PatternCheck,
    PatternInFileCheck,
    PatternInFilePatternCheck,
    PatternInFilesCheck,
    PatternsCheck,
    PatternsInFileCheck,
    PatternsInFilePatternCheck,
    TextCheck,
    TextInFileCheck,
    handle_linguistic_checks,
)


class LinguisticExceptionHandlerTestCase(unittest.TestCase):
    def test_file_check(self):
        check = FileCheck("test")

        self.assertEqual(check.execute("test", None), True)
        self.assertEqual(check.execute("hello", None), False)

    def test_files_check(self):
        check = FilesCheck(["test1", "test2"])

        self.assertEqual(check.execute("test1", None), True)
        self.assertEqual(check.execute("test2", None), True)
        self.assertEqual(check.execute("hello", None), False)

    def test_file_pattern_check(self):
        check = FilePatternCheck(r"test\d")

        self.assertEqual(check.execute("test1", None), True)
        self.assertEqual(check.execute("test2", None), True)
        self.assertEqual(check.execute("Hello1", None), False)

    def test_file_pattern_flag_check(self):
        check = FilePatternCheck(r"test\d", re.IGNORECASE)

        self.assertEqual(check.execute("TEST1", None), True)
        self.assertEqual(check.execute("TEST2", None), True)
        self.assertEqual(check.execute("HELLO1", None), False)

    def test_text_check(self):
        check = TextCheck("test")

        self.assertEqual(check.execute(None, "test"), True)
        self.assertEqual(check.execute(None, "hello"), False)

    def test_pattern_check(self):
        check = PatternCheck(r"test\d")

        self.assertEqual(check.execute(None, "test1"), True)
        self.assertEqual(check.execute(None, "test2"), True)
        self.assertEqual(check.execute(None, "Hello1"), False)

    def test_pattern_flag_check(self):
        check = PatternCheck(r"test\d", re.IGNORECASE)

        self.assertEqual(check.execute(None, "TEST1"), True)
        self.assertEqual(check.execute(None, "TEST2"), True)
        self.assertEqual(check.execute(None, "HELLO1"), False)

    def test_patterns_check(self):
        check = PatternsCheck([r"test\d", r"foo\d"])

        self.assertEqual(check.execute(None, "test1"), True)
        self.assertEqual(check.execute(None, "foo2"), True)
        self.assertEqual(check.execute(None, "HELLO1"), False)

    def test_patterns_tuple_check(self):
        check = PatternsCheck([(r"test\d", 0), (r"foo\d", re.IGNORECASE)])

        self.assertEqual(check.execute(None, "test1"), True)
        self.assertEqual(check.execute(None, "FOO2"), True)
        self.assertEqual(check.execute(None, "HELLO1"), False)

    def test_composite_check(self):
        check = CompositeCheck(FileCheck("test"), TextCheck("test"))

        self.assertEqual(check.execute("test1", "test2"), True)
        self.assertEqual(check.execute("hello", "test2"), False)
        self.assertEqual(check.execute("test1", "hello"), False)
        self.assertEqual(check.execute("hello", "hello"), False)

    def test_text_in_file_check(self):
        check = TextInFileCheck("test", "test")

        self.assertEqual(check.execute("test1", "test2"), True)
        self.assertEqual(check.execute("hello", "test2"), False)
        self.assertEqual(check.execute("test1", "hello"), False)
        self.assertEqual(check.execute("hello", "hello"), False)

    def test_pattern_in_file_check(self):
        check = PatternInFileCheck("test", r"(test|hello)\d")

        self.assertEqual(check.execute("test1", "test2"), True)
        self.assertEqual(check.execute("test1", "hello2"), True)
        self.assertEqual(check.execute("test1", "hello"), False)
        self.assertEqual(check.execute("hello", "hello"), False)

    def test_patterns_in_file_check(self):
        check = PatternsInFileCheck("test", [r"test\d", r"hello\dtest"])

        self.assertEqual(check.execute("test", "test1"), True)
        self.assertEqual(check.execute("test", "hello2test"), True)
        self.assertEqual(check.execute("hello", "test1"), False)
        self.assertEqual(check.execute("test", "TEST1"), False)
        self.assertEqual(check.execute("test", "hello3hello"), False)

    def test_patterns_tuple_in_file_check(self):
        check = PatternsInFileCheck(
            "test", [(r"test\d", re.IGNORECASE), (r"hello\dtest", 0)]
        )

        self.assertEqual(check.execute("test", "test1"), True)
        self.assertEqual(check.execute("test", "TEST2"), True)
        self.assertEqual(check.execute("test", "hello2test"), True)
        self.assertEqual(check.execute("hello", "test1"), False)
        self.assertEqual(check.execute("test", "hello3hello"), False)

    def test_pattern_in_files_check(self):
        check = PatternInFilesCheck(["test", "hello"], r"test\d")

        self.assertEqual(check.execute("1test1", "test1"), True)
        self.assertEqual(check.execute("1hello2", "test2"), True)
        self.assertEqual(check.execute("1foo2", "test2"), False)
        self.assertEqual(check.execute("1hello2", "hello2"), False)

    def test_pattern_in_file_pattern_check(self):
        check = PatternInFilePatternCheck(r"test|hello", r"foo|bar")

        self.assertEqual(check.execute("test1", "foo1"), True)
        self.assertEqual(check.execute("hello1", "bar1"), True)
        self.assertEqual(check.execute("foo1", "test1"), False)

    def test_pattern_in_file_pattern_flags_check(self):
        check = PatternInFilePatternCheck(
            r"test|hello", r"foo|bar", re.IGNORECASE, re.IGNORECASE
        )

        self.assertEqual(check.execute("test1", "foo1"), True)
        self.assertEqual(check.execute("test1", "FOO2"), True)
        self.assertEqual(check.execute("HELLO2", "bar1"), True)
        self.assertEqual(check.execute("foo1", "test1"), False)

    def test_patterns_in_file_pattern_check(self):
        check = PatternsInFilePatternCheck(r"test|hello", [r"foo\d", r"bar\d"])

        self.assertEqual(check.execute("test1", "foo1"), True)
        self.assertEqual(check.execute("hello1", "foo1"), True)

        self.assertEqual(check.execute("test1", "bar1"), True)
        self.assertEqual(check.execute("test1", "bar2"), True)

        self.assertEqual(check.execute("baz1", "bar2"), False)
        self.assertEqual(check.execute("test1", "baz1"), False)
        self.assertEqual(check.execute("baz1", "baz2"), False)

    def test_patterns_in_file_pattern_flags_check(self):
        check = PatternsInFilePatternCheck(
            r"test|hello",
            [(r"foo\d", 0), (r"bar\d", re.IGNORECASE)],
            re.IGNORECASE,
        )

        self.assertEqual(check.execute("test1", "foo1"), True)
        self.assertEqual(check.execute("HELLO", "foo1"), True)

        self.assertEqual(check.execute("test1", "bar1"), True)
        self.assertEqual(check.execute("test1", "BAR2"), True)

        self.assertEqual(check.execute("baz1", "bar2"), False)
        self.assertEqual(check.execute("test1", "BAZ1"), False)
        self.assertEqual(check.execute("baz1", "baz2"), False)

    def test_linguistic_exception_handler(self):
        checks = [FileCheck("test"), TextCheck("foo")]

        self.assertEqual(
            handle_linguistic_checks("test1", "foo1", checks), True
        )
        self.assertEqual(
            handle_linguistic_checks("test1", "bar1", checks), True
        )
        self.assertEqual(
            handle_linguistic_checks("hello1", "foo1", checks), True
        )
        self.assertEqual(
            handle_linguistic_checks("hello1", "bar1", checks), False
        )

# Copyright (C) 2022 Greenbone Networks GmbH
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

import unittest

from troubadix.helper.patterns import (
    ScriptTag,
    SpecialScriptTag,
    get_script_tag_pattern,
    get_script_tag_patterns,
    get_special_script_tag_pattern,
    get_special_script_tag_patterns,
)


class ScriptTagPatternsTestCase(unittest.TestCase):
    def test_same_patterns_instance(self):
        patterns1 = get_script_tag_patterns()
        patterns2 = get_script_tag_patterns()

        self.assertIs(patterns1, patterns2)

    def test_same_pattern_instance(self):
        pattern1 = get_script_tag_pattern(ScriptTag.AFFECTED)
        pattern2 = get_script_tag_pattern(ScriptTag.AFFECTED)

        self.assertIs(pattern1, pattern2)


class SpecialScriptTagPatternsTestCase(unittest.TestCase):
    def test_same_patterns_instance(self):
        patterns1 = get_special_script_tag_patterns()
        patterns2 = get_special_script_tag_patterns()

        self.assertIs(patterns1, patterns2)

    def test_same_pattern_instance(self):
        pattern1 = get_special_script_tag_pattern(
            SpecialScriptTag.ADD_PREFERENCE
        )
        pattern2 = get_special_script_tag_pattern(
            SpecialScriptTag.ADD_PREFERENCE
        )

        self.assertIs(pattern1, pattern2)

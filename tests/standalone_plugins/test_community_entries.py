# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG

import unittest

from troubadix.standalone_plugins.community_entries import (
    is_file_excluded_by_prefix,
    is_infix_present,
)


class CommunityEntriesTestCase(unittest.TestCase):
    def test_is_file_excluded_with_matching_prefix(self):
        self.assertTrue(
            is_file_excluded_by_prefix("nasl/21.04/script.nasl", ["nasl/21.04", "nasl/22.04"])
        )

    def test_is_file_excluded_without_matching_prefix(self):
        self.assertFalse(
            is_file_excluded_by_prefix("nasl/common/script.nasl", ["nasl/21.04", "nasl/22.04"])
        )

    def test_is_file_excluded_with_empty_excludes(self):
        self.assertFalse(is_file_excluded_by_prefix("nasl/21.04/script.nasl", []))

    def test_is_infix_present_with_matching_infix(self):
        self.assertTrue(
            is_infix_present("nasl/common/gsf/enterprise_script.nasl", ["/gsf/", "/internal/"])
        )

    def test_is_infix_present_without_matching_infix(self):
        self.assertFalse(is_infix_present("nasl/common/script.nasl", ["/gsf/", "/internal/"]))

    def test_is_infix_present_with_empty_infixes(self):
        self.assertFalse(is_infix_present("nasl/common/gsf/enterprise_script.nasl", []))

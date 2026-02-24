# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG

import unittest
from pathlib import Path

from troubadix.standalone_plugins.dependency_graph.affected_scripts import run


class TestAffectedScripts(unittest.TestCase):
    def setUp(self):
        # point to merged generated-feed layout for tests
        self.feed_root = Path("tests/standalone_plugins/nasl_feed")
        self.input_file = Path("tests/standalone_plugins/changed_files.txt")
        self.output_file = Path("tests/standalone_plugins/affected_files.txt")

        # Ensure files exist for argparse
        self.input_file.touch()
        self.output_file.touch()

    def tearDown(self):
        if self.input_file.exists():
            self.input_file.unlink()
        if self.output_file.exists():
            self.output_file.unlink()

    def test_affected_scripts_basic(self):
        # foo.nasl depends on foobar.nasl
        # foobar.nasl depends on bar.nasl
        # bar.nasl depends on foo.nasl
        # foo.nasl depends on lib.inc (via include)

        # This forms a cycle: foo -> foobar -> bar -> foo

        # If bar.nasl changes, then bar, foobar, and foo should be affected.
        self.input_file.write_text("nasl/common/bar.nasl\n")

        run(self.feed_root, self.input_file, self.output_file)

        affected = self.output_file.read_text().splitlines()
        self.assertIn("bar.nasl", affected)
        self.assertIn("foobar.nasl", affected)
        self.assertIn("foo.nasl", affected)
        self.assertIn("22_script.nasl", affected)
        # lib.inc is not affected by bar.nasl because bar.nasl depends on it (via foo)
        self.assertNotIn("lib.inc", affected)
        self.assertEqual(len(affected), 4)

    def test_affected_scripts_include(self):
        # If lib.inc changes, then foo.nasl should be affected,
        # and because of the cycle, bar.nasl and foobar.nasl too.
        self.input_file.write_text("nasl/common/lib.inc\n")

        run(self.feed_root, self.input_file, self.output_file)

        affected = self.output_file.read_text().splitlines()
        self.assertIn("bar.nasl", affected)
        self.assertIn("foobar.nasl", affected)
        self.assertIn("foo.nasl", affected)
        self.assertIn("22_script.nasl", affected)
        self.assertIn("lib.inc", affected)
        self.assertEqual(len(affected), 5)

    def test_affected_scripts_max_distance(self):
        # bar.nasl -> foobar.nasl -> foo.nasl
        # distance from bar.nasl: bar.nasl (0), foobar.nasl (1), foo.nasl (2)

        self.input_file.write_text("nasl/common/bar.nasl\n")

        run(self.feed_root, self.input_file, self.output_file, max_distance=1)

        affected = self.output_file.read_text().splitlines()
        self.assertIn("bar.nasl", affected)
        self.assertIn("foobar.nasl", affected)
        self.assertNotIn("foo.nasl", affected)
        self.assertEqual(len(affected), 2)

    # Note: prefix stripping behavior is implicit in the input normalization
    # and covered by other tests; no separate prefix-stripping test required.

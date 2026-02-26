import unittest
from pathlib import Path

from troubadix.standalone_plugins.affected_scripts import run


class TestAffectedScriptsStandalone(unittest.TestCase):
    def setUp(self):
        self.root = Path("tests/standalone_plugins/nasl_feed")
        self.input_file = self.root.parent / "changed_files.txt"
        self.output_file = self.root.parent / "affected_files.txt"

        self.input_file.parent.mkdir(parents=True, exist_ok=True)
        # ensure files exist
        self.input_file.touch()
        self.output_file.touch()

    def tearDown(self):
        if self.input_file.exists():
            self.input_file.unlink()
        if self.output_file.exists():
            self.output_file.unlink()

    def test_standalone_file(self):
        self.input_file.write_text("nasl/common/standalone.nasl\n")
        run(self.root, self.input_file, self.output_file)
        affected = self.output_file.read_text().splitlines()
        # Only the standalone file should be affected
        self.assertEqual(affected, ["standalone.nasl"])

    def test_foo_changed(self):
        self.input_file.write_text("nasl/22.04/gsf/foo.nasl\n")
        run(self.root, self.input_file, self.output_file)
        affected = self.output_file.read_text().splitlines()
        # Only foo.nasl should be affected
        self.assertEqual(affected, ["gsf/foo.nasl"])

    def test_bar_changed(self):
        self.input_file.write_text("bar.nasl\n")
        run(self.root, self.input_file, self.output_file)
        affected = self.output_file.read_text().splitlines()
        # bar.nasl and foo.nasl should be affected (foo depends on bar)
        self.assertIn("bar.nasl", affected)
        self.assertIn("gsf/foo.nasl", affected)
        self.assertEqual(len(affected), 2)

    def test_foobar_changed(self):
        self.input_file.write_text("nasl/common/gsf/foobar.nasl\n")
        run(self.root, self.input_file, self.output_file)
        affected = self.output_file.read_text().splitlines()
        # foobar.nasl and foo.nasl should be affected (foo depends on foobar)
        self.assertIn("gsf/foobar.nasl", affected)
        self.assertIn("gsf/foo.nasl", affected)
        self.assertEqual(len(affected), 2)

    def test_barfoo_changed(self):
        self.input_file.write_text("barfoo.nasl\n")
        run(self.root, self.input_file, self.output_file)
        affected = self.output_file.read_text().splitlines()
        # barfoo.nasl, bar.nasl, and foo.nasl should be affected
        # foo depends on bar, bar depends on barfoo
        self.assertIn("barfoo.nasl", affected)
        self.assertIn("bar.nasl", affected)
        self.assertIn("gsf/foo.nasl", affected)
        self.assertEqual(len(affected), 3)

    def test_lib_inc_include(self):
        self.input_file.write_text("lib.inc\n")
        run(self.root, self.input_file, self.output_file)
        affected = self.output_file.read_text().splitlines()
        # lib.inc is included by foo.nasl and barfoo.nasl, which propagate up
        self.assertIn("lib.inc", affected)
        self.assertIn("gsf/foo.nasl", affected)
        self.assertIn("barfoo.nasl", affected)
        self.assertIn("bar.nasl", affected)  # bar depends on barfoo
        self.assertEqual(len(affected), 4)

    def test_empty_input(self):
        self.input_file.write_text("")
        run(self.root, self.input_file, self.output_file)
        affected = self.output_file.read_text().splitlines()
        self.assertEqual(len(affected), 0)

    def test_max_distance(self):
        # barfoo.nasl depends on lib.inc
        # bar.nasl depends on barfoo.nasl
        # foo.nasl depends on bar.nasl and others
        self.input_file.write_text("barfoo.nasl\n")

        # Distance 0: only barfoo.nasl
        run(self.root, self.input_file, self.output_file, max_distance=0)
        affected = self.output_file.read_text().splitlines()
        self.assertEqual(affected, ["barfoo.nasl"])

        # Distance 1: barfoo.nasl and its direct ancestor bar.nasl
        run(self.root, self.input_file, self.output_file, max_distance=1)
        affected = self.output_file.read_text().splitlines()
        self.assertIn("barfoo.nasl", affected)
        self.assertIn("bar.nasl", affected)
        self.assertEqual(len(affected), 2)

        # Distance 2: barfoo.nasl, bar.nasl, and foo.nasl
        run(self.root, self.input_file, self.output_file, max_distance=2)
        affected = self.output_file.read_text().splitlines()
        self.assertIn("barfoo.nasl", affected)
        self.assertIn("bar.nasl", affected)
        self.assertIn("gsf/foo.nasl", affected)
        self.assertEqual(len(affected), 3)

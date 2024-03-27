# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG

import tempfile
import unittest
from pathlib import Path

from troubadix.standalone_plugins.file_extensions import (
    check_extensions,
    parse_args,
)


class TestFileExtensions(unittest.TestCase):
    def test_ok(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tempfile.mkstemp(dir=tmpdir, suffix=".nasl")
            tempfile.mkstemp(dir=tmpdir, suffix=".inc")
            child_dir = tempfile.mkdtemp(dir=tmpdir)
            tempfile.mkstemp(dir=child_dir, suffix=".nasl")
            parsed_args = parse_args(["-d", tmpdir])
            self.assertFalse(check_extensions(parsed_args))

    def test_fail(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fp1 = Path(tempfile.mkstemp(dir=tmpdir, suffix=".nasl.nasl")[1])
            fp2 = Path(tempfile.mkstemp(dir=tmpdir, suffix=".inc.inc")[1])
            fp3 = Path(tempfile.mkstemp(dir=tmpdir, suffix=".nasl.inc")[1])
            fp4 = Path(tempfile.mkstemp(dir=tmpdir, suffix=".inc.nasl")[1])
            child_dir = tempfile.mkdtemp(dir=tmpdir)
            fp5 = Path(tempfile.mkstemp(dir=child_dir, suffix=".bar")[1])
            expected = {fp1, fp2, fp3, fp4, fp5}
            parsed_args = parse_args(["-d", tmpdir])
            actual = check_extensions(parsed_args)
            self.assertTrue(actual)
            self.assertEqual(set(actual), expected)


if __name__ == "__main__":
    unittest.main()

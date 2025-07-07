# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG
import io
import os
import sys
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from troubadix.standalone_plugins.file_extensions import (
    check_extensions,
    main,
    parse_args,
)


class TestFileExtensions(unittest.TestCase):
    def test_ok(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # foo.nasl / foo.inc
            tempfile.mkstemp(dir=tmpdir, suffix=".nasl")
            tempfile.mkstemp(dir=tmpdir, suffix=".inc")

            # files in subfolders
            child_dir = tempfile.mkdtemp(dir=tmpdir)
            tempfile.mkstemp(dir=child_dir, suffix=".nasl")
            tempfile.mkstemp(dir=child_dir, suffix=".inc")

            parsed_args = Namespace(dir=Path(tmpdir), ignore_file=None)
            self.assertFalse(check_extensions(parsed_args))

    def test_exclusions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # manual exclusions
            new_dir = os.path.join(tmpdir, "common")
            os.mkdir(new_dir)
            with open(
                os.path.join(new_dir, "bad_rsa_ssh_host_keys.txt"),
                "w",
                encoding="utf-8",
            ):
                pass

            with open(os.path.join(tmpdir, "README.md"), "w", encoding="utf-8"):
                pass

            with open(
                os.path.join(tmpdir, "file_extension.ignore"),
                "a",
                encoding="utf-8",
            ) as f:
                exclusions = [
                    "README.md\n",
                    "common/bad_rsa_ssh_host_keys.txt\n",
                    "#ignore comment line",
                ]
                f.writelines(exclusions)

            parsed_args = Namespace(
                dir=Path(tmpdir),
                ignore_file=Path(tmpdir, "file_extension.ignore"),
            )
            actual = check_extensions(parsed_args)
            self.assertTrue(actual)
            self.assertEqual(actual, [Path(tmpdir, "file_extension.ignore")])

    def test_fail(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # foo.nasl.nasl
            fp1 = Path(tempfile.mkstemp(dir=tmpdir, suffix=".nasl.nasl")[1])
            # foo.inc.inc
            fp2 = Path(tempfile.mkstemp(dir=tmpdir, suffix=".inc.inc")[1])
            # foo.nasl.inc
            fp3 = Path(tempfile.mkstemp(dir=tmpdir, suffix=".nasl.inc")[1])
            # foo.inc.nasl
            fp4 = Path(tempfile.mkstemp(dir=tmpdir, suffix=".inc.nasl")[1])
            child_dir = tempfile.mkdtemp(dir=tmpdir)
            # foo.bar
            fp5 = Path(tempfile.mkstemp(dir=child_dir, suffix=".bar")[1])
            # .foo
            fp6 = Path(tempfile.mkstemp(dir=child_dir, prefix=".")[1])
            # foo
            fp7 = Path(tempfile.mkstemp(dir=child_dir)[1])

            expected = {fp1, fp2, fp3, fp4, fp5, fp6, fp7}
            parsed_args = Namespace(dir=Path(tmpdir), ignore_file=None)
            actual = check_extensions(parsed_args)
            self.assertTrue(actual)
            self.assertEqual(set(actual), expected)

    def test_parse_args_ok(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(
                os.path.join(tmpdir, "file_extensions.ignore"),
                "w",
                encoding="utf-8",
            ):
                pass
            test_args = [
                "prog",
                tmpdir,
                "--ignore-file",
                f"{tmpdir}/file_extensions.ignore",
            ]
            with patch.object(sys, "argv", test_args):
                args = parse_args()
                self.assertTrue(args)
                self.assertEqual(args.dir, Path(tmpdir))
                self.assertEqual(
                    args.ignore_file, Path(tmpdir, "file_extensions.ignore")
                )

    def test_parse_args_no_dir(self):
        test_args = ["prog", "not_real_dir"]
        with redirect_stderr(io.StringIO()) as f:
            with patch.object(sys, "argv", test_args):
                with self.assertRaises(SystemExit):
                    parse_args()
                self.assertRegex(f.getvalue(), "invalid directory_type")

    def test_parse_args_no_file(self):
        with redirect_stderr(io.StringIO()) as f:
            with tempfile.TemporaryDirectory() as tmpdir:
                test_args = ["prog", tmpdir, "--ignore-file", "not_real_file"]
                with patch.object(sys, "argv", test_args):
                    with self.assertRaises(SystemExit):
                        parse_args()
                    self.assertRegex(f.getvalue(), "invalid file_type")

    def test_main_ok(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tempfile.mkstemp(dir=tmpdir, suffix=".nasl")
            test_args = ["prog", tmpdir]
            with patch.object(sys, "argv", test_args):
                self.assertFalse(main())

    def test_main_fail(self):
        with StringIO() as buffer, redirect_stdout(buffer):
            with tempfile.TemporaryDirectory() as tmpdir:
                tempfile.mkstemp(dir=tmpdir)
                test_args = ["prog", tmpdir]
                with patch.object(sys, "argv", test_args):
                    self.assertTrue(main())


if __name__ == "__main__":
    unittest.main()

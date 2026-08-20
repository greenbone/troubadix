# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG

import io
from contextlib import redirect_stdout
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from tests.plugins import TemporaryDirectory
from troubadix.standalone_plugins.malicious_nasl_check import (
    main,
    parse_arguments,
    parse_vts,
)


class MaliciousNaslCheckTestCase(TestCase):
    def test_parse_arguments_default(self):
        with patch("sys.argv", ["prog"]):
            args = parse_arguments()

        self.assertEqual(args.vt_dir, Path("vts"))

    def test_parse_arguments_custom_vt_dir(self):
        with patch("sys.argv", ["prog", "--vt-dir", "custom-vts"]):
            args = parse_arguments()

        self.assertEqual(args.vt_dir, Path("custom-vts"))

    def test_parse_vts_accepts_whitelisted_include_and_command(self):
        with TemporaryDirectory() as tempdir:
            vt_file = tempdir / "allowed.nasl"
            vt_file.write_text(
                'include("version_func.inc");\n'
                "if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))\n"
                '  get_kb_item(name:"Settings/OS");\n',
                encoding="LATIN-1",
            )

            result = parse_vts(tempdir)

        self.assertEqual(result, [])

    def test_parse_vts_reports_unexpected_include(self):
        with TemporaryDirectory() as tempdir:
            vt_file = tempdir / "unexpected_include.nasl"
            vt_file.write_text(
                'include("unknown_file.inc");\n',
                encoding="LATIN-1",
            )

            result = parse_vts(tempdir)

        self.assertEqual(result, [vt_file])

    def test_parse_vts_reports_unexpected_command(self):
        with TemporaryDirectory() as tempdir:
            vt_file = tempdir / "unexpected_command.nasl"
            vt_file.write_text(
                'include("version_func.inc");\n' 'system("id");\n',
                encoding="LATIN-1",
            )

            result = parse_vts(tempdir)

        self.assertEqual(result, [vt_file])

    def test_parse_vts_scans_nested_nasl_files_only(self):
        with TemporaryDirectory() as tempdir:
            nested_dir = tempdir / "nested"
            nested_dir.mkdir()

            vt_file = nested_dir / "unexpected.nasl"
            vt_file.write_text('exec("sh");\n', encoding="LATIN-1")

            ignored_file = tempdir / "unexpected.txt"
            ignored_file.write_text('exec("sh");\n', encoding="LATIN-1")

            result = parse_vts(tempdir)

        self.assertEqual(result, [vt_file])

    def test_main_returns_zero_without_errors(self):
        with TemporaryDirectory() as tempdir:
            vt_file = tempdir / "allowed.nasl"
            vt_file.write_text(
                'include("version_func.inc");\n'
                "if (TRUE) {\n"
                '  get_kb_item(name:"Settings/OS");\n'
                "}\n",
                encoding="LATIN-1",
            )

            with patch("sys.argv", ["prog", "--vt-dir", str(tempdir)]):
                result = main()

        self.assertEqual(result, 0)

    def test_main_returns_one_and_prints_files_with_errors(self):
        with TemporaryDirectory() as tempdir:
            vt_file = tempdir / "blocked.nasl"
            vt_file.write_text('system("id");\n', encoding="LATIN-1")

            stdout = io.StringIO()
            with redirect_stdout(stdout), patch("sys.argv", ["prog", "--vt-dir", str(tempdir)]):
                result = main()

        self.assertEqual(result, 1)
        self.assertIn("1 Files with unexpected NASL methods were found:", stdout.getvalue())
        self.assertIn(str(vt_file), stdout.getvalue())

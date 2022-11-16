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

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path

from pontos.terminal.terminal import ConsoleTerminal

from troubadix.standalone_plugins.no_solution import (
    check_no_solutions,
    check_skip_script,
    extract_tags,
    parse_solution_date,
    print_info,
    print_report,
)


class ParseArgsTestCase(unittest.TestCase):
    def test_parse_solution_date(self):
        test_values = [
            ("01st August, 2022", datetime(2022, 8, 1)),
            ("02nd August, 2022", datetime(2022, 8, 2)),
            ("03rd August, 2022", datetime(2022, 8, 3)),
            ("04th August, 2022", datetime(2022, 8, 4)),
        ]

        for test_value, expected_result in test_values:
            result = parse_solution_date(test_value)
            self.assertEqual(result, expected_result)

    def test_check_skip_script_ok(self):
        content = (
            'script_tag(name:"solution_type", value:"NoneAvailable");\n”'
            'script_tag(name:"cvss_base", value:"6.4");\n'
        )

        result = check_skip_script(content)
        self.assertEqual(result, False)

    def test_check_skip_script_nok_cvss(self):
        content = (
            'script_tag(name:"solution_type", value:"NoneAvailable");\n”'
            'script_tag(name:"cvss_base", value:"0.0");\n'
        )

        result = check_skip_script(content)
        self.assertEqual(result, True)

    def test_check_skip_script_nok_solution_type(self):
        content = (
            'script_tag(name:"solution_type", value:"VendorFix");\n”'
            'script_tag(name:"cvss_base", value:"6.4");\n'
        )

        result = check_skip_script(content)
        self.assertEqual(result, True)

    def test_extract_tags_ok(self):
        content = (
            'script_tag(name:"solution", value:"No known solution is '
            "available as of 05th August, 2022. Information regarding "
            "this issue will be updated once solution details"
            ' are available.");\n'
            'script_tag(name:"creation_date", value:"2021-07-21 16:20:50'
            ' +0200 (Wed, 21 Jul 2021)");\n'
            'script_oid("1.3.6.1.4.1.25623.1.0.118132");\n'
        )

        expected_result = (
            datetime(2022, 8, 5),
            datetime(2021, 7, 21),
            "1.3.6.1.4.1.25623.1.0.118132",
        )

        result = extract_tags(content)

        self.assertEqual(result, expected_result)

    def test_extract_tags_break_solution_1(self):
        content = (
            'script_tag(name:"creation_date", value:"2021-07-21 16:20:50'
            ' +0200 (Wed, 21 Jul 2021)");\n'
            'script_oid("1.3.6.1.4.1.25623.1.0.118132");\n'
        )

        expected_result = None

        result = extract_tags(content)

        self.assertEqual(result, expected_result)

    def test_extract_tags_break_solution_2(self):
        content = (
            'script_tag(name:"solution", value:"No known solution is '
            "available as in 05th August, 2022. Information regarding "
            "this issue will be updated once solution details"
            ' are available.");\n'
            'script_tag(name:"creation_date", value:"2021-07-21 16:20:50'
            ' +0200 (Wed, 21 Jul 2021)");\n'
            'script_oid("1.3.6.1.4.1.25623.1.0.118132");\n'
        )

        expected_result = None

        result = extract_tags(content)

        self.assertEqual(result, expected_result)

    def test_extract_tags_break_solution_3(self):
        content = (
            'script_tag(name:"solution", value:"No known solution is '
            "available as of 05th Imaginary, 2022. Information regarding "
            "this issue will be updated once solution details"
            ' are available.");\n'
            'script_tag(name:"creation_date", value:"2021-07-21 16:20:50'
            ' +0200 (Wed, 21 Jul 2021)");\n'
            'script_oid("1.3.6.1.4.1.25623.1.0.118132");\n'
        )

        expected_result = None

        result = extract_tags(content)

        self.assertEqual(result, expected_result)

    def test_extract_tags_break_creation_date(self):
        content = (
            'script_tag(name:"solution", value:"No known solution is '
            "available as of 05th August, 2022. Information regarding "
            "this issue will be updated once solution details are"
            ' available.");\n'
            'script_oid("1.3.6.1.4.1.25623.1.0.118132");\n'
        )

        expected_result = None

        result = extract_tags(content)

        self.assertEqual(result, expected_result)

    def test_extract_tags_break_oid(self):
        content = (
            'script_tag(name:"solution", value:"No known solution is '
            "available as of 05th August, 2022. Information regarding "
            "this issue will be updated once solution details are "
            'available.");\n'
            'script_tag(name:"creation_date", value:"2021-07-21 16:20:50'
            ' +0200 (Wed, 21 Jul 2021)");\n'
        )

        expected_result = None

        result = extract_tags(content)

        self.assertEqual(result, expected_result)

    def test_check_no_solutions(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_file = Path(tmp_dir, "file.txt")
            test_file.touch()

            with open(test_file, "w", encoding="LATIN-1") as file_stream:
                content = (
                    'script_oid("1.3.6.1.4.1.25623.1.0.118132");\n'
                    'script_tag(name:"creation_date", value:"2021-07-21 '
                    '16:20:50 +0200 (Wed, 21 Jul 2021)");\n'
                    'script_tag(name:"cvss_base", value:"6.4");\n'
                    'script_tag(name:"solution_type", value:"NoneAvailable");\n'
                    'script_tag(name:"solution", value:"No known solution'
                    " is available as of 05th August, 2022.Information "
                    "regarding this issue will be "
                    'updated once solution details are available.");\n'
                )
                file_stream.write(content)

            result = check_no_solutions([test_file], [12, 6, 1])

            expected_result = [
                (
                    12,
                    [
                        (
                            test_file,
                            "1.3.6.1.4.1.25623.1.0.118132",
                            datetime(2022, 8, 5),
                        )
                    ],
                )
            ]

            self.assertEqual(result, expected_result)

    def test_print_info(self):

        term = ConsoleTerminal()

        with redirect_stdout(io.StringIO()) as f:
            print_info(term, [12, 6, 1], 12, "/home/test")

        result = f.getvalue()

        # Control chars from terminal output included
        expected_result = (
            "\x1b[1m\x1b[38;2;0;255;255mℹ\x1b[39m\x1b[1m Reported VTs "
            "with solution type 'NoneAvailable'\x1b[22m\n\x1b[0m\x1b["
            "38;2;255;255;255m \x1b[39m\x1b[0m     Root directory: "
            "/home/test\x1b[0m\n\x1b[0m\x1b[38;2;255;255;255m "
            "\x1b[39m\x1b[0m     Milestones: 12, 6, 1 "
            "months\x1b[0m\n\x1b[0m\x1b[38;2;255;255;255m "
            "\x1b[39m\x1b[0m     Expect no solution threshold: "
            "12 months\x1b[0m\n"
        )

        self.assertEqual(result, expected_result)

    def test_print_report(self):
        term = ConsoleTerminal()

        summary = [
            (
                12,
                [
                    (
                        Path("/home/test/vt1.nasl"),
                        "1.2.3",
                        datetime(2022, 1, 1),
                    )
                ],
            ),
            (
                6,
                [
                    (
                        Path("/home/test/vt2.nasl"),
                        "1.2.4",
                        datetime(2021, 7, 1),
                    )
                ],
            ),
            (
                1,
                [
                    (
                        Path("/home/test/vt3.nasl"),
                        "1.2.5",
                        datetime(2021, 1, 1),
                    )
                ],
            ),
        ]

        with redirect_stdout(io.StringIO()) as f:
            print_report(term, summary, 12, Path("/home/test"))

        result = f.getvalue()

        # Control chars from terminal output included
        expected_result = (
            "\x1b[0m\x1b[38;2;0;255;255mℹ\x1b[39m\x1b[0m"
            " Total VTs without solution: 3\n  "
            "\x1b[0m\n\x1b[1m\x1b[38;2;0;255;255mℹ\x1b[39m\x1b[1m "
            "1 VTs with no solution for more than 12 month(s).\n  "
            "No solution should be expected at this point. "
            "\x1b[22m\n\x1b[0m\x1b[38;2;0;255;255mℹ\x1b[39m\x1b[0m "
            "vt1.nasl\x1b[0m\n\x1b[0m\x1b[38;2;255;255;255m \x1b[39m\x1b[0m"
            "     File: vt1.nasl\x1b[0m\n\x1b[0m\x1b[38;2;255;255;255m "
            "\x1b[39m\x1b[0m     OID: 1.2.3\x1b[0m\n\x1b[0m\x1b"
            "[38;2;255;255;255m \x1b[39m\x1b[0m     Last solution "
            "update: 2022-01-01\x1b[0m\n\x1b[0m\x1b[38;2;255;255;255m "
            "\x1b[39m\x1b[0m \x1b[0m\n\x1b[1m\x1b[38;2;0;255;255mℹ\x1b"
            "[39m\x1b[1m 1 VTs with no solution for more than 6 month(s)"
            "\x1b[22m\n\x1b[0m\x1b[38;2;0;255;255mℹ\x1b[39m\x1b[0m "
            "vt2.nasl\x1b[0m\n\x1b[0m\x1b[38;2;255;255;255m \x1b[39m\x1b[0m"
            "     File: vt2.nasl\x1b[0m\n\x1b[0m\x1b[38;2;255;255;255m "
            "\x1b[39m\x1b[0m     OID: 1.2.4\x1b[0m\n\x1b[0m\x1b"
            "[38;2;255;255;255m \x1b[39m\x1b[0m     Last solution update: "
            "2021-07-01\x1b[0m\n\x1b[0m\x1b[38;2;255;255;255m \x1b[39m\x1b[0m "
            "\x1b[0m\n\x1b[1m\x1b[38;2;0;255;255mℹ\x1b[39m\x1b[1m 1 VTs with "
            "no solution for more than 1 month(s)\x1b[22m\n\x1b[0m\x1b"
            "[38;2;0;255;255mℹ\x1b[39m\x1b[0m vt3.nasl\x1b[0m\n\x1b[0m\x1b"
            "[38;2;255;255;255m \x1b[39m\x1b[0m     File: vt3.nasl\x1b"
            "[0m\n\x1b[0m\x1b[38;2;255;255;255m \x1b[39m\x1b[0m     OID: "
            "1.2.5\x1b[0m\n\x1b[0m\x1b[38;2;255;255;255m \x1b[39m\x1b[0m"
            "     Last solution update: 2021-01-01\x1b[0m\n\x1b[0m\x1b"
            "[38;2;255;255;255m \x1b[39m\x1b[0m \x1b[0m\n"
        )

        self.assertEqual(result, expected_result)

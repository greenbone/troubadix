# Copyright (C) 2021 Greenbone Networks GmbH
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

""" Argument parser for naslinter """

from argparse import ArgumentParser, Namespace
from pathlib import Path
import sys


def directory_type(string: str) -> Path:
    directory_path = Path(string)
    if not directory_path.is_dir():
        raise ValueError(f"{string} is not a directory")
    return directory_path


def file_type(string: str) -> Path:
    file_path = Path(string)
    if not file_path.is_file():
        raise ValueError(f"{string} is not a directory")
    return file_path


def parse_args(args: Namespace = None) -> Namespace:
    """Parsing args for nasl-lint"""

    parser = ArgumentParser(
        description="Greenbone NASL File Linter.",
    )

    parser.add_argument(
        "-f",
        "--full",
        action="store_true",
        help=(
            "Checking the complete VT directory and "
            "not only the added/changed scripts"
        ),
    )

    what_group = parser.add_mutually_exclusive_group()

    what_group.add_argument(
        "-d",
        "--dirs",
        nargs="+",
        type=directory_type,
        help="List of directories that should be linted",
    )

    what_group.add_argument(
        "--files",
        nargs="+",
        type=file_type,
        help="List of files that should be linted",
    )

    what_group.add_argument(
        "--commit-range",
        nargs="+",
        type=str,
        help=(
            "Allows to specify a git commit range "
            '(e.g. "$commit-hash1 $commit-hash2" or '
            '"HEAD~1") to run the QA test against.'
        ),
    )

    what_group.add_argument(
        "--staged-only",
        action="store_true",
        help=('Only run against files which are "staged/added" in git'),
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help=("Enables the DEBUG output"),
    )

    parser.add_argument(
        "--non-recursive",
        action="store_true",
        help='Don\'t run the script recursive. Only usable with "-f"/"--full"',
    )

    parser.add_argument(
        "--include-regex",
        type=str,
        help=(
            "Allows to specify a regex (glob) to "
            'limit the "full" run to specific file names. '
            'Only usable with "-f"/"--full"'
        ),
    )

    parser.add_argument(
        "--exclude-regex",
        type=str,
        help=(
            "Allows to specify a regex (glob) to "
            'exclude specific file names from the "full" run. '
            'Only usable with "-f"/"--full"'
        ),
    )

    tests_group = parser.add_mutually_exclusive_group(required=False)

    tests_group.add_argument(
        "--include-tests",
        type=str,
        nargs="+",
        help=(
            "Allows to choose which tests should be run in this lint. "
            "Only the given tests will run."
        ),
    )

    tests_group.add_argument(
        "--exclude-tests",
        type=str,
        nargs="+",
        help=(
            "Allows to exclude tests from this lint. "
            "All tests excluding the given will run."
        ),
    )

    parser.add_argument(
        "--skip-duplicated-oids",
        action="store_true",
        help=" Disables the check for duplicated OIDs in VTs",
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stdout)
        sys.exit(1)

    return parser.parse_args(args=args)

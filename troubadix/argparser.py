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

""" Argument parser for troubadix """

import sys
from argparse import ArgumentParser, Namespace
from multiprocessing import cpu_count
from pathlib import Path
from typing import List

from pontos.terminal import info, warning


def directory_type(string: str) -> Path:
    directory_path = Path(string)
    if directory_path.exists() and not directory_path.is_dir():
        raise ValueError(f"{string} is not a directory.")
    return directory_path


def file_type(string: str) -> Path:
    file_path = Path(string)
    if file_path.exists() and not file_path.is_file():
        raise ValueError(f"{string} is not a file.")
    return file_path


def check_cpu_count(number: str) -> int:
    """Make sure this value is valid
    Default: use half of the available cores to not block the machine"""
    max_count = cpu_count()
    if not number:
        return max_count // 2
    number = int(number)
    if number > max_count:
        return max_count
    if number < 1:
        return max_count // 2
    return number


def parse_args(
    *,
    args: List[str] = None,
) -> Namespace:
    """Parsing args for nasl-lint

    Arguments:
    args        The program arguments passed by exec"""

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

    what_group = parser.add_mutually_exclusive_group(required=False)

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
        "--from-file",
        type=file_type,
        help=(
            "Pass a file that contains a List of files "
            "containing paths to files, that should be "
            "checked. Files should be separated by newline"
        ),
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
        help='Only run against files which are "staged/added" in git',
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help=("-v verbose, -vv debug"),
    )
    parser.add_argument(
        "--log-file",
        dest="log_file",
        type=file_type,
        help=("Log file path"),
    )

    parser.add_argument(
        "--non-recursive",
        action="store_true",
        help=(
            "Don't run the script recursive. "
            'Only usable with "-f"/"--full" or "-d"/"--dirs"'
        ),
    )

    parser.add_argument(
        "--include-patterns",
        type=str,
        nargs="+",
        help=(
            "Allows to specify pattern(s) (glob) to "
            'limit the "--full"/"--dirs" run to specific file names. '
            'e.g. "gb_*.nasl", or "*some_vt*.nasl" or "some_dir/gb_*nasl". '
            'Only usable with "-f"/"--full" or "-d"/"--dirs".'
        ),
    )

    parser.add_argument(
        "--exclude-patterns",
        type=str,
        nargs="+",
        help=(
            "Allows to specify pattern(s) (glob) to "
            'exclude specific file names from the "--full"/"--dirs" run. '
            'e.g. "some_dir/*.nasl", "gb_*nasl", "*/anything.*'
            'Only usable with "-f"/"--full" or "-d"/"--dirs".'
        ),
    )

    tests_group = parser.add_mutually_exclusive_group(required=False)

    tests_group.add_argument(
        "--include-tests",
        type=str,
        nargs="+",
        dest="included_plugins",
        help=(
            "Allows to choose which tests should be run in this lint. "
            "Only the given tests will run. Valid as CamelCase and snake_case."
        ),
    )

    tests_group.add_argument(
        "--exclude-tests",
        type=str,
        nargs="+",
        dest="excluded_plugins",
        help=(
            "Allows to exclude tests from this lint. "
            "All tests excluding the given will run. "
            "Valid as CamelCase and snake_case."
        ),
    )

    tests_group.add_argument(
        "--update-date",
        action="store_true",
        help=(
            "Run troubadix in update modification_date and "
            "script_version mode. Attention: This will modify all "
            "passed files."
        ),
    )

    parser.add_argument(
        "--skip-duplicated-oids",
        action="store_true",
        help=" Disables the check for duplicated OIDs in VTs",
    )

    parser.add_argument(
        "-j",
        "--n-jobs",
        dest="n_jobs",
        default=cpu_count() // 2,
        type=check_cpu_count,
        help=(
            "Define number of jobs, that should run simultaneously"
            "Default: %(default)s"
        ),
    )

    parser.add_argument(
        "--no-statistic",
        action="store_true",
        help="Don't print the statistic",
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stdout)
        sys.exit(1)

    parsed_args = parser.parse_args(args=args)

    # Full will run in the root directory of executing. (Like pwd)
    if parsed_args.full:
        cwd = Path.cwd()
        info(f"Running full lint from {cwd}")
        parsed_args.dirs = [cwd]

    if not parsed_args.dirs and (
        parsed_args.include_patterns or parsed_args.exclude_patterns
    ):
        warning(
            "The arguments '--include-patterns' and '--exclude-patterns' "
            "must be used with '-f/--full' or '-d'/'--dirs'"
        )
        sys.exit(1)

    if not parsed_args.dirs and parsed_args.non_recursive:
        warning(
            "'Argument '--non-recursive' is only usable with "
            "'-f'/'--full' or '-d'/'--dirs'"
        )
        sys.exit(1)

    return parsed_args

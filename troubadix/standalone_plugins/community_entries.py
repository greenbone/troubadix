# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later


import os
from argparse import ArgumentParser, Namespace

from troubadix.standalone_plugins.common import git


def parse_arguments() -> Namespace:
    parser = ArgumentParser(
        "Tool to check for files which would be newly added to the community part of the VTS repo"
    )

    parser.add_argument("ref_a", help="The ref to diff from")

    parser.add_argument("ref_b", help="The ref to diff to")

    parser.add_argument(
        "-d", "--directory", help="The directory containing the repositry to work in"
    )

    parser.add_argument(
        "--required-infix",
        dest="required_infixes",
        type=str,
        nargs="+",
        default=["/gsf/"],
        help="Infix required to avoid reporting",
    )

    parser.add_argument(
        "--exclude-prefix",
        dest="excluded_prefixes",
        type=str,
        nargs="+",
        default=["nasl/21.04"],
        help="Prefix to exclude from reporting",
    )

    return parser.parse_args()


def is_file_excluded(file: str, excludes: list[str]) -> bool:
    return any(True for exclude in excludes if file.startswith(exclude))


def is_infix_present(file: str, infixes: list[str]) -> bool:
    return any(True for infix in infixes if infix in file)


def main():

    arguments = parse_arguments()

    os.chdir(arguments.directory)

    files = git(
        "diff", arguments.ref_b, arguments.ref_a, "--name-only", "--diff-filter=A", "--no-renames"
    ).splitlines()

    valid_files = (
        file for file in files if not is_file_excluded(file, arguments.excluded_prefixes)
    )

    report_files = (
        file for file in valid_files if not is_infix_present(file, arguments.required_infixes)
    )

    for file in report_files:
        print(file)


if __name__ == "__main__":
    main()

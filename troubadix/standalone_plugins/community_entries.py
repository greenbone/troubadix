# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later


import os
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser, Namespace

from troubadix.standalone_plugins.common import git


def parse_arguments() -> Namespace:
    parser = ArgumentParser(
        "Tool to check for files which would be newly added to the community part of the VTS repo",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("ref_from", help="The ref to diff from. Example: 'HEAD'")

    parser.add_argument("ref_to", help="The ref to diff to. Example: 'main'")

    parser.add_argument(
        "-d", "--directory", help="The directory containing the repository to work in"
    )

    parser.add_argument(
        "--required-infix",
        dest="required_infixes",
        type=str,
        nargs="*",
        default=["/gsf/"],
        help="Infix required to avoid reporting",
    )

    parser.add_argument(
        "--exclude-prefix",
        dest="excluded_prefixes",
        type=str,
        nargs="*",
        default=["nasl/21.04", "nasl/22.04"],
        help="Prefix to exclude from reporting",
    )

    parser.add_argument(
        "--allowed-extension",
        dest="allowed_extensions",
        type=str,
        nargs="*",
        default=["nasl", "inc"],
        help="File extensions required for reporting",
    )

    return parser.parse_args()


def is_file_excluded_by_prefix(file: str, excludes: list[str]) -> bool:
    return any(True for exclude in excludes if file.startswith(exclude))


def is_infix_present(file: str, infixes: list[str]) -> bool:
    return any(True for infix in infixes if infix in file)


def execute_git_diff(arguments: Namespace) -> list[str]:
    file_extension_wildcards = [f"*.{extension}" for extension in arguments.allowed_extensions]

    return git(
        "diff",
        arguments.ref_to,
        arguments.ref_from,
        "--name-only",
        "--diff-filter=A",
        "--no-renames",
        "--",
        *file_extension_wildcards,
    ).splitlines()


def main():
    arguments = parse_arguments()

    if arguments.directory:
        os.chdir(arguments.directory)

    files = execute_git_diff(arguments)

    valid_files = (
        file for file in files if not is_file_excluded_by_prefix(file, arguments.excluded_prefixes)
    )

    report_files = (
        file for file in valid_files if not is_infix_present(file, arguments.required_infixes)
    )

    for file in report_files:
        print(file)


if __name__ == "__main__":
    main()

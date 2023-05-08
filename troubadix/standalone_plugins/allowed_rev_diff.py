# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later


import re
from argparse import ArgumentParser, Namespace
from pathlib import Path
from re import Pattern
from typing import List

from git.repo.base import Repo

DEFAULT_IGNORED_LINESTARTS = ["diff ", "index ", "--- ", "+++ ", "@@ "]


def ensure_pattern(argument: str) -> Pattern:
    return re.compile(argument)


def parse_arguments() -> Namespace:
    argument_parser = ArgumentParser(
        "Tool to check that the target rev only has diffs conforming to "
        "the given patterns regarding the source rev"
    )

    argument_parser.add_argument(
        "-d",
        "--directory",
        default=Path.cwd(),
        type=Path,
        help="The directory the repository to check is located in. "
        "Defaults to 'pwd'",
    )

    ignored_linestart_group = argument_parser.add_mutually_exclusive_group()

    ignored_linestart_group.add_argument(
        "-i",
        "--ignored-linestarts",
        dest="ignored_linestarts",
        nargs="*",
        type=str,
        default=DEFAULT_IGNORED_LINESTARTS,
        help="A list of line starts which will make the line be ignored. "
        "Default: %(default)s",
    )

    ignored_linestart_group.add_argument(
        "--ignored-linestart-file",
        type=read_ignored_linestarts,
        dest="ignored_linestarts",
        default=DEFAULT_IGNORED_LINESTARTS,
        help="The file containing a list of line starts, "
        "separated by newlines, which will make the line be ignored. "
        "Default values used: %(default)s",
    )

    pattern_group = argument_parser.add_mutually_exclusive_group(required=True)

    pattern_group.add_argument(
        "-p",
        "--patterns",
        type=ensure_pattern,
        nargs="*",
        help="The list of patterns to check the diff for",
    )

    pattern_group.add_argument(
        "--pattern-file",
        type=Path,
        help="The file containing the list of patterns, separated by newlines, "
        "to check the diff for",
    )

    argument_parser.add_argument(
        "-s", "--source", type=str, required=True, help="The upstream rev"
    )

    argument_parser.add_argument(
        "-t", "--target", type=str, required=True, help="The downstream rev"
    )

    return argument_parser.parse_args()


def check_diff_line_starts_with_ignored_linestart(
    line: str, ignored_linestarts: List[str]
) -> bool:
    return any(
        linestart
        for linestart in ignored_linestarts
        if line.startswith(linestart)
    )


def check_diff_line_matches_pattern(line: str, patterns: List[Pattern]) -> bool:
    return any(pattern for pattern in patterns if pattern.match(line))


def check_diff(
    lines: List[str], ignored_linestarts: List[str], patterns: List[Pattern]
) -> List[str]:
    return [
        line
        for line in lines
        if not check_diff_line_starts_with_ignored_linestart(
            line, ignored_linestarts
        )
        and not check_diff_line_matches_pattern(line, patterns)
    ]


def read_ignored_linestarts(path: Path) -> List[str]:
    if not path:
        return None

    with open(path, "r", encoding="UTF-8") as file:
        return [line.removesuffix("\n") for line in file.readlines()]


def read_patterns(path: Path) -> List[Pattern]:
    with open(path, "r", encoding="UTF-8") as file:
        return [
            re.compile(pattern.removesuffix("\n"))
            for pattern in file.readlines()
        ]


def main() -> int:
    arguments = parse_arguments()

    patterns = arguments.patterns or read_patterns(arguments.pattern_file)

    repo = Repo(arguments.directory)

    target = repo.commit(arguments.target)

    merge_base = repo.merge_base(repo.commit(arguments.source), target)[0]

    diff = repo.git.diff(target, merge_base, unified=0)

    result = check_diff(
        diff.splitlines(), arguments.ignored_linestarts, patterns
    )

    if result:
        print("The following lines don't match the any pattern:")
        print("\n".join(result))

        return 1

    return 0


if __name__ == "__main__":
    main()

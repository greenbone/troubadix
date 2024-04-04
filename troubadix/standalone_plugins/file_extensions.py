# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG

import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path
from typing import List


def directory_type(string: str) -> Path:
    directory_path = Path(string)
    if not directory_path.is_dir():
        raise ValueError(f"{string} is not a directory.")
    return directory_path


def file_type(string: str) -> Path:
    directory_path = Path(string)
    if not directory_path.is_file():
        raise ValueError(f"{string} is not a directory.")
    return directory_path


def parse_args() -> Namespace:
    parser = ArgumentParser(
        description="Check for files with unwanted file extensions",
    )
    parser.add_argument(
        "dir",
        type=directory_type,
        help="directory that should be linted",
    )
    parser.add_argument(
        "--ignore-file", type=file_type, help="path to ignore file"
    )
    return parser.parse_args()


def create_exclusions(args: Namespace) -> List[Path]:
    exclusions = []
    if args.ignore_file is not None:
        with open(args.ignore_file, "r", encoding="utf-8") as file:
            for line in file:
                if line.startswith("#"):
                    continue
                exclusions.append(Path(line.strip()))
    return exclusions


def check_extensions(args: Namespace) -> List[Path]:
    """This script checks for any non .nasl or .inc file."""
    unwanted_files: List[Path] = []
    allowed_extensions = [".inc", ".nasl"]
    exclusions = create_exclusions(args)
    for item in args.dir.rglob("*"):
        if item.is_file():
            relative_path = item.relative_to(args.dir)

            if relative_path in exclusions:
                continue

            # foo.inc.inc / foo.nasl.nasl
            # foo.inc.nasl / foo.nasl.inc
            if len(item.suffixes) > 1:
                unwanted_files.append(item)

            # foo / foo.bar
            if item.suffix not in allowed_extensions:
                unwanted_files.append(item)

    return unwanted_files


def main() -> int:
    if unwanted_files := check_extensions(parse_args()):
        print(
            f"{len(unwanted_files)} "
            "Files with unwanted file extension were found:"
        )
        for file in unwanted_files:
            print(file)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

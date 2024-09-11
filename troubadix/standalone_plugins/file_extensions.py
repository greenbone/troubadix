# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG

import re
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
    file_path = Path(string)
    if not file_path.is_file():
        raise ValueError(f"{string} is not a file.")
    return file_path


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
    parser.add_argument(
        "--gen-ignore-entries",
        action="store_true",
        help="output only newline seperated entries, no header",
    )
    return parser.parse_args()


def create_exclusions(ignore_file: Path) -> set[Path]:
    if ignore_file is None:
        return set()

    with open(ignore_file, "r", encoding="utf-8") as file:
        return {
            Path(line.strip()) for line in file if not re.match(r"^\s*#", line)
        }


def check_extensions(args: Namespace) -> List[Path]:
    """This script checks for any non .nasl or .inc file."""
    unwanted_files: List[Path] = []
    allowed_extensions = [".inc", ".nasl"]
    exclusions = create_exclusions(args.ignore_file)

    for item in args.dir.rglob("*"):
        if not item.is_file():
            continue

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
    args = parse_args()
    unwanted_files = check_extensions(args)
    if not unwanted_files:
        return 0

    if args.gen_ignore_entries:
        for file in unwanted_files:
            print(file.relative_to(args.dir))
        return 0

    print(
        f"{len(unwanted_files)} "
        "Files with unwanted file extension were found:"
    )
    for file in unwanted_files:
        print(file)
    return 1


if __name__ == "__main__":
    sys.exit(main())

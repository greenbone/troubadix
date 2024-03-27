# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG

import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path
from typing import Iterable, List


def directory_type(string: str) -> Path:
    directory_path = Path(string)
    if directory_path.exists() and not directory_path.is_dir():
        raise ValueError(f"{string} is not a directory.")
    return directory_path


def parse_args(args: Iterable[str]) -> Namespace:
    parser = ArgumentParser(
        description="Check for changed oid",
    )
    parser.add_argument(
        "-d",
        "--dirs",
        nargs="+",
        type=directory_type,
        help="List of directories that should be linted",
    )
    return parser.parse_args(args=args)


def check_extensions(args: Namespace) -> List[Path]:
    """This script checks for any non .nasl or .inc file."""
    dirs = args.dirs
    unwanted_files: List[Path] = []
    allowed_extensions = [".inc", ".nasl"]
    for directory in dirs:
        for item in directory.rglob("*"):
            if item.is_file():
                # foo.inc.inc / foo.nasl.nasl
                if (
                    item.suffixes.count(".inc") > 1
                    or item.suffixes.count(".nasl") > 1
                ):
                    unwanted_files.append(item)

                # foo.inc.nasl / foo.nasl.inc
                if all(
                    extension in item.suffixes
                    for extension in allowed_extensions
                ):
                    unwanted_files.append(item)

                # foo / foo.bar
                if item.suffix not in allowed_extensions:
                    unwanted_files.append(item)

    return unwanted_files


def main() -> int:
    args = sys.argv[1:]
    if unwanted_files := check_extensions(parse_args(args)):
        print("Files with unwanted file extension were found:")
        for file in unwanted_files:
            print(file)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

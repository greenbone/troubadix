# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG

import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path
from typing import List

exclusions: List[str] = [
    "/common/bad_rsa_ssh_host_keys.txt",
    "/common/bad_dsa_ssh_host_keys.txt",
    "/22.04/.git-keep",
    "/21.04/.git-keep",
    "/README.md",
]


def directory_type(string: str) -> Path:
    directory_path = Path(string)
    if not directory_path.is_dir():
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
    return parser.parse_args()


def check_extensions(args: Namespace) -> List[Path]:
    """This script checks for any non .nasl or .inc file."""
    unwanted_files: List[Path] = []
    allowed_extensions = [".inc", ".nasl"]
    for item in args.dir.rglob("*"):
        if item.is_file():
            if any(str(item).endswith(exclusion) for exclusion in exclusions):
                continue
            # foo.inc.inc / foo.nasl.nasl
            if (
                item.suffixes.count(".inc") > 1
                or item.suffixes.count(".nasl") > 1
            ):
                unwanted_files.append(item)

            # foo.inc.nasl / foo.nasl.inc
            if all(
                extension in item.suffixes for extension in allowed_extensions
            ):
                unwanted_files.append(item)

            # foo / foo.bar
            if item.suffix not in allowed_extensions:
                unwanted_files.append(item)

    return unwanted_files


def main() -> int:
    if unwanted_files := check_extensions(parse_args()):
        print("Files with unwanted file extension were found:")
        for file in unwanted_files:
            print(file)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

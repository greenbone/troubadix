# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

import os
import re
import subprocess
import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path
from typing import Iterable

from troubadix.argparser import file_type_existing
from troubadix.standalone_plugins.common import git


def parse_args(args: Iterable[str]) -> Namespace:
    parser = ArgumentParser(
        description="Check for changed creation date",
    )
    parser.add_argument(
        "-c",
        "--commit_range",
        type=str,
        required=True,
        help=(
            "Git commit range to check e.g "
            "2c87f4b6062804231fd508411510ca07fd270380^..HEAD or"
            "YOUR_BRANCH..main"
        ),
    )
    parser.add_argument(
        "-f",
        "--files",
        nargs="+",
        type=file_type_existing,
        default=[],
        help=(
            "List of files to diff. "
            "If empty use all files added or modified in the commit range."
        ),
    )
    return parser.parse_args(args=args)


def check_changed_creation_date(args: Namespace) -> bool:
    """
    This script checks (via git diff) if the creation date of
    a passed VT has changed, which is not allowed.
    """

    if not args.files:
        args.files += [
            Path(f)
            for f in git(
                "diff", "--name-only", "--diff-filter=d", args.commit_range
            ).splitlines()
        ]

    creation_date_changed = False

    for nasl_file in args.files:
        if nasl_file.suffix != ".nasl" or not nasl_file.exists():
            continue

        print(f"Check file {nasl_file}")
        text = git(
            "-c",
            "color.status=false",
            "--no-pager",
            "diff",
            args.commit_range,
            nasl_file,
        )

        creation_date_added = re.search(
            r"^\+\s*script_tag\s*\(\s*name\s*:\s*\"creation_date\"\s*,"
            r"\s*value\s*:\s*\"(?P<creation_date>.*)\"\s*\)\s*;",
            text,
            re.MULTILINE,
        )
        if not creation_date_added or not (
            added := creation_date_added.group("creation_date")
        ):
            continue

        creation_date_removed = re.search(
            r"^\-\s*script_tag\s*\(\s*name\s*:\s*\"creation_date\"\s*,"
            r"\s*value\s*:\s*\"(?P<creation_date>.*)\"\s*\)\s*;",
            text,
            re.MULTILINE,
        )
        if not creation_date_removed or not (
            removed := creation_date_removed.group("creation_date")
        ):
            continue

        if added != removed:
            print(
                f"The creation date of {nasl_file} was changed, "
                f"which is not allowed."
                f"\nNew creation date: "
                f"{added}"
                f"\nOld creation date: "
                f"{removed}",
                file=sys.stderr,
            )
            creation_date_changed = True

    return creation_date_changed


def main() -> int:

    try:
        git_base = git("rev-parse", "--show-toplevel")
        os.chdir(git_base.rstrip("\n"))
    except subprocess.SubprocessError:
        print(
            "Your current working directory doesn't belong to a git repository"
        )
        return 1

    if check_changed_creation_date(parse_args(sys.argv[1:])):
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())

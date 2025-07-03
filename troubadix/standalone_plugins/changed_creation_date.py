# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

import logging
import os
import re
import subprocess
import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path

from troubadix.argparser import file_type_existing
from troubadix.standalone_plugins.common import git

logger = logging.getLogger(__name__)

CREATION_DATE_BASE_PATTERN = (
    r"\s*script_tag\s*\(\s*name\s*:\s*\"creation_date\"\s*,"
    r"\s*value\s*:\s*\"(?P<creation_date>.*)\"\s*\)\s*;"
)


def parse_arguments() -> Namespace:

    parser = ArgumentParser(
        description="Check for changed creation date",
    )
    parser.add_argument(
        "-c",
        "--commit_range",
        type=str,
        required=True,
        help=(
            "Git commit range to check e.g. "
            "2c87f4b6062804231fd508411510ca07fd270380..HEAD or"
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
    args = parser.parse_args()

    if not args.files:
        args.files += [
            Path(filename)
            for filename in git(
                "diff", "--name-only", "--diff-filter=d", args.commit_range
            ).splitlines()
            if filename.endswith(".nasl")
        ]

    return args


def check_changed_creation_date(
    commit_range: str, nasl_files: list[Path]
) -> bool:
    """
    This script checks (via git diff) if the creation date of
    passed VTs has changed, which is not allowed.
    """
    creation_date_changed = False

    for nasl_file in nasl_files:

        if not nasl_file.exists():
            continue

        logger.info("Check file %s", nasl_file)
        text = git(
            "-c",
            "color.status=false",
            "--no-pager",
            "diff",
            commit_range,
            nasl_file,
        )

        creation_date_added = re.search(
            r"^\+" + CREATION_DATE_BASE_PATTERN,
            text,
            re.MULTILINE,
        )
        if not creation_date_added or not (
            added := creation_date_added.group("creation_date")
        ):
            continue

        creation_date_removed = re.search(
            r"^\-" + CREATION_DATE_BASE_PATTERN,
            text,
            re.MULTILINE,
        )
        if not creation_date_removed or not (
            removed := creation_date_removed.group("creation_date")
        ):
            continue

        if added != removed:
            logger.error(
                "The creation date of %s was changed, "
                "which is not allowed.\nNew creation date: "
                "%s\nOld creation date: %s",
                nasl_file,
                added,
                removed,
            )
            creation_date_changed = True

    return creation_date_changed


def main() -> int:

    try:
        git_base = git("rev-parse", "--show-toplevel")
        os.chdir(git_base.rstrip("\n"))
    except subprocess.SubprocessError:
        logger.error(
            "Your current working directory doesn't belong to a git repository"
        )
        return 1

    args = parse_arguments()
    if check_changed_creation_date(args.commit_range, args.files):
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())

# Copyright (C) 2022 Greenbone Networks GmbH
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

import os
import re
import subprocess
import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path
from typing import Iterable, List

from troubadix.helper.patterns import (
    LAST_MODIFICATION_ANY_VALUE_PATTERN,
    SCRIPT_VERSION_ANY_VALUE_PATTERN,
)

SCRIPT_VERSION_PATTERN = re.compile(
    r"^\+\s*" + SCRIPT_VERSION_ANY_VALUE_PATTERN, re.MULTILINE
)
SCRIPT_LAST_MODIFICATION_PATTERN = re.compile(
    r"^\+\s*" + LAST_MODIFICATION_ANY_VALUE_PATTERN, re.MULTILINE
)


def file_type(string: str) -> Path:
    file_path = Path(string)
    if not file_path.is_file():
        raise ValueError(f"{string} is not a file.")
    return file_path


def parse_args(args: Iterable[str]) -> Namespace:
    parser = ArgumentParser(
        description="Check for changed files that did not alter "
        "last_modification and script_version",
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
        type=file_type,
        default=[],
        help=(
            "List of files to diff."
            "If empty use all files added or modifyed in the"
            " commit range"
        ),
    )
    return parser.parse_args(args=args)


def git(*args) -> str:
    # git diff output uses raw bytes
    return subprocess.run(
        ["git"] + list(args),
        capture_output=True,
        encoding="latin-1",
        check=True,
    ).stdout


def check_version_updated(files: List[Path], commit_range: str) -> bool:
    """The script checks (via git diff) if the passed VT has changed the
    the following tags:

    - script_version("[...]");
    - script_tag(name:"last_modification", value:"[...]");
    """

    if not files:
        files = [
            Path(f)
            for f in git(
                "diff", "--name-only", "--diff-filter=d", commit_range
            ).splitlines()
        ]

    rcode = True
    for nasl_file in files:
        if nasl_file.suffix != ".nasl" or not nasl_file.exists():
            continue

        print(f"Check file {nasl_file}")
        text = git(
            "-c",
            "color.status=false",
            "--no-pager",
            "diff",
            commit_range,
            nasl_file,
        )

        if not SCRIPT_VERSION_PATTERN.search(text):
            print(
                f"{nasl_file}: Missing updated script_version", file=sys.stderr
            )
            rcode = False

        if not SCRIPT_LAST_MODIFICATION_PATTERN.search(text):
            print(
                f"{nasl_file}: Missing updated last_modification",
                file=sys.stderr,
            )
            rcode = False

    return rcode


def main() -> int:
    args = sys.argv[1:]

    try:
        git_base = git("rev-parse", "--show-toplevel")
        os.chdir(git_base.rstrip("\n"))
    except subprocess.SubprocessError:
        print(
            "Your current working directory doesn't belong to a git repository"
        )
        return 1

    parsed_args = parse_args(args)
    if not check_version_updated(parsed_args.files, parsed_args.commit_range):
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())

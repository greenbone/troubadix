# Copyright (C) 2022 Greenbone AG
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
from typing import Iterable

from troubadix.standalone_plugins.common import git


def file_type(string: str) -> Path:
    file_path = Path(string)
    if not file_path.is_file():
        raise ValueError(f"{string} is not a file.")
    return file_path


def parse_args(args: Iterable[str]) -> Namespace:
    parser = ArgumentParser(
        description="Check for changed oid",
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
            "List of files to diff. "
            "If empty use all files added or modified in the commit range."
        ),
    )
    return parser.parse_args(args=args)


def check_oid(args: Namespace) -> bool:
    """The script checks (via git diff) if the passed VT has changed the
    OID in the following tag:

    - script_oid("1.2.3");

    This is only allowed in rare cases (e.g. a single VT was split into
    two VTs).
    """

    if not args.files:
        args.files += [
            Path(f)
            for f in git(
                "diff", "--name-only", "--diff-filter=d", args.commit_range
            ).splitlines()
        ]

    rcode = False
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

        oid_added = re.search(
            r'^\+\s*script_oid\s*\(\s*["\'](?P<oid>[0-9.]+)["\']\s*\)\s*;',
            text,
            re.MULTILINE,
        )
        if not oid_added or not oid_added.group("oid"):
            continue

        oid_removed = re.search(
            r'^-\s*script_oid\s*\(\s*["\'](?P<oid>[0-9.]+)["\']\s*\)\s*;',
            text,
            re.MULTILINE,
        )
        if not oid_removed or not oid_removed.group("oid"):
            continue

        if oid_added.group("oid") != oid_removed.group("oid"):
            print(
                f"OID of VT {nasl_file} was changed. This is only allowed in "
                f"rare cases (e.g. a duplicate OID got fixed or a single VT "
                f"was split into two VTs)."
                f"\nOID NEW: {oid_added.group('oid')}"
                f"\nOID OLD: {oid_removed.group('oid')}",
                file=sys.stderr,
            )
            rcode = True
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

    if check_oid(parse_args(args)):
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())

# Copyright (C) 2023 Greenbone AG
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


import re
from argparse import ArgumentParser, Namespace
from pathlib import Path
from subprocess import CalledProcessError
from typing import Iterable, List

from pontos.terminal.terminal import ConsoleTerminal

from troubadix.argparser import file_type
from troubadix.standalone_plugins.changed_packages.marker import (
    AddedEpoch,
    AddedRelease,
    AddedUdeb,
    ChangedUpdate,
    DroppedArchitecture,
)
from troubadix.standalone_plugins.changed_packages.package import (
    Package,
    Reasons,
)
from troubadix.standalone_plugins.common import get_merge_base, git

PACKAGE_CHECK_PATTERN = re.compile(
    r'isdpkgvuln\(pkg:"(?P<package>[^"]+)", ver:"(?P<version>[^"]+)", '
    r'rls:"(?P<release>[^"]+)"\)'
)


def compare(old_content: str, content: str):
    old_packages = get_packages(old_content)
    packages = get_packages(content)

    missing_packages = sorted(old_packages.difference(packages))
    new_packages = sorted(packages.difference(old_packages))

    AddedEpoch.mark(missing_packages, new_packages)
    AddedRelease.mark(old_packages, new_packages)
    AddedUdeb.mark(new_packages)
    ChangedUpdate.mark(missing_packages, new_packages)
    DroppedArchitecture.mark(missing_packages, new_packages)

    return missing_packages, new_packages


def filter_reasons(packages: List[Package], reasons: Iterable[Reasons]):
    return [
        package
        for package in packages
        if not package.reasons
        or any([reason not in reasons for reason in package.reasons])
    ]


def print_results(
    missing_packages: List[Package],
    new_packages: List[Package],
    file: Path,
    terminal: ConsoleTerminal,
):
    terminal.warning(f"Packages for {file} differ")

    if missing_packages:
        terminal.print("Missing packages")
        print_packages(missing_packages, terminal)

    if new_packages:
        terminal.print("New packages")
        print_packages(new_packages, terminal)


def print_packages(
    packages: List[Package],
    terminal: ConsoleTerminal,
):
    with terminal.indent():
        for package in packages:
            terminal.print(f"{package}")


def get_packages(content: str):
    package_checks = PACKAGE_CHECK_PATTERN.findall(content)
    result = {
        Package(name=name, version=version, release=release)
        for name, version, release in package_checks
    }

    if len(result) != len(package_checks):
        raise ValueError("There are duplicate checks. Cannot compare.")

    return result


def parse_args() -> Namespace:
    parser = ArgumentParser(
        description="Check for changed packages in dpkg-based LSCs",
    )
    parser.add_argument(
        "--files",
        nargs="+",
        type=file_type,
        default=[],
        required=True,
        help="List of files to check.",
    )
    parser.add_argument(
        "--start-commit",
        type=str,
        required=False,
        help=(
            "The commit before the changes to check have been introduced. "
            "If the files have been renamed before, choose that commit. "
            "Defaults to the merge-base with main"
        ),
        default=get_merge_base("main", "HEAD"),
    )
    parser.add_argument(
        "--hide-equal",
        action="store_true",
        help="Omit log message, if a file has equal checks",
    )
    parser.add_argument(
        "--hide-reasons",
        nargs="*",
        action="extend",
        default=[],
        type=Reasons.from_cli_argument,
        choices=list(Reasons),
        help="Disable the output for packages that changed for a given reason",
    )

    return parser.parse_args()


def main():
    args = parse_args()
    hide_reasons = set(args.hide_reasons)
    terminal = ConsoleTerminal()

    terminal.info(
        f"Checking {len(args.files)} file(s) from {args.start_commit} to HEAD"
    )

    for file in args.files:
        try:
            old_content = git("show", f"{args.start_commit}:{file}")
            content = git("show", f"HEAD:{file}")
            missing_packages, new_packages = compare(old_content, content)
        except CalledProcessError:
            terminal.error(
                f"Could not find {file} at {args.start_commit} or HEAD"
            )
            continue
        except ValueError as e:
            terminal.error(f"Error while handling {file}: {e}")
            continue

        if not missing_packages and not new_packages:
            if not args.hide_equal:
                terminal.info(f"{file} has equal checks")
            continue

        missing_packages = filter_reasons(missing_packages, hide_reasons)
        new_packages = filter_reasons(new_packages, hide_reasons)

        if not missing_packages and not new_packages and hide_reasons:
            terminal.info(f"Packages for {file} differ, but reasons are hidden")
            continue

        print_results(
            missing_packages,
            new_packages,
            file,
            terminal,
        )


if __name__ == "__main__":
    main()

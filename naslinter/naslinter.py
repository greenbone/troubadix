# Copyright (C) 2021 Greenbone Networks GmbH
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

""" Main module for naslinter """

from pathlib import Path
from typing import List
from pontos.terminal.terminal import Terminal

from naslinter.argparser import parse_args
from naslinter.runner import Runner


def generate_file_list(
    dirs: List[Path], exclude_regex: List[str], dglobs: List[str]
) -> List[Path]:
    """Generates a files list under respect of several given arguments

    Arguments:
    dirs            List of dirs, within looking for files
    exclude_regex   List of glob patterns, exclude files that fit the pattern
    dglobs          List of glob patterns, include files that fit the pattern
                    with respect of excluded files

    Returns
    List of Path objects"""
    files: List[Path] = []
    for directory in dirs:
        for dglob in dglobs:
            files.extend([f for f in directory.glob(dglob)])
    if exclude_regex:
        excluded_files = []
        for directory in dirs:
            for exclude in exclude_regex:
                excluded_files.extend([f for f in directory.glob(exclude)])
        files = [f for f in files if f not in excluded_files]

    return files


def generate_patterns(
    include_regex: List[str],
    exclude_regex: List[str],
    non_recursive: bool,
    term: Terminal,
) -> List[str]:
    """Generates the include and exclude patterns

    Arguments:
    include_regex   List of glob patterns to filter files with
    exclude_regex   List of glob patterns of files that will excluded
    non_recursive   Wether to include all subdirs to the patterns or not

    Returns
    List of Path objects"""
    # Setting the globs for non-recursive/recursive:
    # Setting the globs for include regexes:
    if include_regex:
        dglobs = [include_regex]
    else:
        # no regex, check all nasl and inc files
        dglobs = ["*.nasl", "*.inc"]

    if not non_recursive:
        # if non-recursive (default), add recursive pattern to globs
        dglobs = [f"**/{dglob}" for dglob in dglobs]
        if exclude_regex:
            exclude_regex = [f"**/{excl}" for excl in exclude_regex]
    else:
        term.warning("Running in not recurive mode!")

    return dglobs, exclude_regex


def main(args=None):
    """Main process of greenbone-docker"""
    term = Terminal()

    parsed_args = parse_args(term=term, args=args)

    runner = Runner(
        excluded_plugins=parsed_args.excluded_plugins,
        included_plugins=parsed_args.included_plugins,
        terminal=term,
    )

    dglobs, parsed_args.exclude_regex = generate_patterns(
        include_regex=parsed_args.include_regex,
        exclude_regex=parsed_args.exclude_regex,
        non_recursive=parsed_args.non_recursive,
        term=term,
    )

    parsed_args.files = generate_file_list(
        dirs=parsed_args.dirs,
        exclude_regex=parsed_args.exclude_regex,
        dglobs=dglobs,
    )

    if parsed_args.files:
        print("Running files ... ")
        runner.run(parsed_args.files)
    else:
        term.warning("No files given/found.")


if __name__ == "__main__":
    main()

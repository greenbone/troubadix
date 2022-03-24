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

""" Main module for troubadix """

import sys
from pathlib import Path
from typing import List, Tuple

from pontos.terminal import _set_terminal, error, info, warning
from pontos.terminal.terminal import Terminal

from troubadix.argparser import parse_args
from troubadix.helper import get_root
from troubadix.runner import Runner


def generate_file_list(
    dirs: List[Path], exclude_patterns: List[str], include_patterns: List[str]
) -> List[Path]:
    """Generates a files list under respect of several given arguments

    Arguments:
    dirs                List of dirs, within looking for files
    exclude_patterns    List of glob patterns,
                        exclude files that fit the pattern
    include_patterns    List of glob patterns,
                        include files that fit the pattern
                        with respect of excluded files

    Returns
    List of Path objects"""
    files: List[Path] = []
    for directory in dirs:
        for pattern in include_patterns:
            files.extend(directory.glob(pattern))
    if exclude_patterns:
        excluded_files = []
        for directory in dirs:
            for pattern in exclude_patterns:
                excluded_files.extend(directory.glob(pattern))
        files = [f for f in files if f not in excluded_files]

    return files


def generate_patterns(
    include_patterns: List[str],
    exclude_patterns: List[str],
    non_recursive: bool,
) -> Tuple[List[str], List[str]]:
    """Generates the include and exclude patterns

    Arguments:
    include_patterns    List of glob patterns to filter files with
    exclude_patterns    List of glob patterns of files that will excluded
    non_recursive       Whether to include all subdirs to the patterns or not

    Returns
    Corrected tuple of lists of include and exclude patterns"""
    # Setting the globs for include all nasl and inc files, if no include
    # pattern given
    if not include_patterns:
        include_patterns = ["*.nasl", "*.inc"]

    if not non_recursive:
        # if non-recursive (default), add recursive pattern to globs
        include_patterns = [f"**/{pattern}" for pattern in include_patterns]
        if exclude_patterns:
            exclude_patterns = [f"**/{pattern}" for pattern in exclude_patterns]
    else:
        warning("Running in non-recursive mode!")

    return include_patterns, exclude_patterns


def from_file(include_file: Path, term: Terminal):
    """Parse the given file containing a list of files into"""
    try:
        return [
            Path(f)
            for f in include_file.read_text(encoding="utf-8").splitlines()
        ]
    except FileNotFoundError:
        term.error(f"File {include_file} containing the file list not found.")
        sys.exit(1)


def main(args=None):
    """Main process of greenbone-docker"""
    term = Terminal()
    _set_terminal(term)

    parsed_args = parse_args(args=args)

    runner = Runner(
        n_jobs=parsed_args.n_jobs,
        term=term,
        excluded_plugins=parsed_args.excluded_plugins,
        included_plugins=parsed_args.included_plugins,
        update_date=parsed_args.update_date,
        verbose=parsed_args.verbose,
        statistic=True if not parsed_args.no_statistic else False,
        log_file=parsed_args.log_file,
    )

    if parsed_args.dirs:
        (
            parsed_args.include_patterns,
            parsed_args.exclude_patterns,
        ) = generate_patterns(
            include_patterns=parsed_args.include_patterns,
            exclude_patterns=parsed_args.exclude_patterns,
            non_recursive=parsed_args.non_recursive,
        )

        parsed_args.files = generate_file_list(
            dirs=parsed_args.dirs,
            exclude_patterns=parsed_args.exclude_patterns,
            include_patterns=parsed_args.include_patterns,
        )

    if parsed_args.from_file:
        parsed_args.files = from_file(
            include_file=parsed_args.from_file, term=term
        )

    if parsed_args.files:
        # Get the root of the nasl files
        if not get_root(parsed_args.files[0].resolve()):
            error(
                "Root directory of VTs not found. Looked for "
                f"{parsed_args.files[0].resolve()}"
            )
            sys.exit(1)
        info(f"Start linting {len(parsed_args.files)} files ... ")
        runner.run(parsed_args.files)
    else:
        warning("No files given/found.")


if __name__ == "__main__":
    main()

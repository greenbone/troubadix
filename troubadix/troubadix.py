# Copyright (C) 2021 Greenbone AG
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

"""Main module for troubadix"""

import sys
from collections.abc import Iterable
from pathlib import Path

from pontos.terminal import Terminal
from pontos.terminal.terminal import ConsoleTerminal

from troubadix.__version__ import __version__
from troubadix.argparser import parse_args
from troubadix.helper import get_root
from troubadix.reporter import Reporter
from troubadix.runner import Runner


def generate_file_list(
    dirs: Iterable[Path],
    exclude_patterns: Iterable[str],
    include_patterns: Iterable[str],
) -> list[Path]:
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
    files: list[Path] = []
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
    terminal: ConsoleTerminal,
    include_patterns: list[str],
    exclude_patterns: list[str],
    non_recursive: bool,
) -> tuple[list[str], list[str]]:
    """Generates the include and exclude patterns

    Arguments:
        include_patterns:    List of glob patterns to filter files with
        exclude_patterns:    List of glob patterns of files that will excluded
        non_recursive:       Whether to include all sub directories to the
                            patterns or not

    Returns:
        Corrected tuple of lists of include and exclude patterns
    """
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
        terminal.warning("Running in non-recursive mode!")

    return include_patterns, exclude_patterns


def from_file(include_file: Path, term: Terminal) -> Iterable[Path]:
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
    term = ConsoleTerminal()

    if not args:
        args = sys.argv[1:]

    parsed_args = parse_args(terminal=term, args=args)

    if parsed_args.version:
        term.info(f"troubadix version {__version__}")
        sys.exit(1)

    # Full will run in the root directory of executing. (Like pwd)
    if parsed_args.full:
        cwd = Path.cwd()
        dirs = [cwd]
        term.info(f"Running full lint from {cwd}")
    else:
        dirs = parsed_args.dirs

    files = None
    if dirs:
        include_patterns, exclude_patterns = generate_patterns(
            terminal=term,
            include_patterns=parsed_args.include_patterns,
            exclude_patterns=parsed_args.exclude_patterns,
            non_recursive=parsed_args.non_recursive,
        )

        files = generate_file_list(
            dirs=dirs,
            exclude_patterns=exclude_patterns,
            include_patterns=include_patterns,
        )

    elif parsed_args.from_file:
        files = from_file(include_file=parsed_args.from_file, term=term)

    elif parsed_args.files:
        files = parsed_args.files

    if not files:
        term.warning("No files given/found.")
        sys.exit(1)

    # Remove duplicate files
    files = list(set(files))

    # Get the root of the nasl files
    if parsed_args.root:
        root = parsed_args.root
    else:
        first_file = files[0].resolve()
        root = get_root(first_file)

    reporter = Reporter(
        term=term,
        fix=parsed_args.fix,
        log_file=parsed_args.log_file,
        log_file_statistic=parsed_args.log_file_statistic,
        root=root,
        statistic=True if not parsed_args.no_statistic else False,
        verbose=parsed_args.verbose,
        ignore_warnings=parsed_args.ignore_warnings,
    )

    runner = Runner(
        reporter=reporter,
        n_jobs=parsed_args.n_jobs,
        excluded_plugins=parsed_args.excluded_plugins,
        included_plugins=parsed_args.included_plugins,
        fix=parsed_args.fix,
        ignore_warnings=parsed_args.ignore_warnings,
        root=root,
    )

    term.info(f"Start linting {len(files)} files ... ")

    # Return exit with 1 if error exist
    if not runner.run(files):
        sys.exit(1)


if __name__ == "__main__":
    main()

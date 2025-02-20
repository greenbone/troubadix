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

"""updating the modification time in VTs that have been touched/edited"""

import datetime
import re
import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path
from typing import Iterable, Sequence

from pontos.terminal import Terminal
from pontos.terminal.terminal import ConsoleTerminal

from troubadix.argparser import file_type_existing
from troubadix.helper import CURRENT_ENCODING
from troubadix.helper.patterns import (
    LAST_MODIFICATION_ANY_VALUE_PATTERN,
    SCRIPT_VERSION_ANY_VALUE_PATTERN,
)
from troubadix.troubadix import from_file


def update(nasl_file: Path, terminal: Terminal):
    file_content = nasl_file.read_text(encoding=CURRENT_ENCODING)

    # update modification date
    tag_template = 'script_tag(name:"last_modification", value:"{date}");'

    match_last_modification_any_value = re.search(
        pattern=LAST_MODIFICATION_ANY_VALUE_PATTERN,
        string=file_content,
    )

    if not match_last_modification_any_value:
        terminal.warning(
            f'Ignoring "{nasl_file}" because it is missing a last_modification tag.'
        )
        return

    now = datetime.datetime.now(datetime.timezone.utc)
    # get that date formatted correctly:
    # "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)"
    correctly_formatted_datetime = f"{now:%Y-%m-%d %H:%M:%S %z (%a, %d %b %Y)}"

    file_content = file_content.replace(
        match_last_modification_any_value.group(0),
        tag_template.format(date=correctly_formatted_datetime),
    )

    # update script version
    script_version_template = 'script_version("{date}");'

    match_script_version = re.search(
        pattern=SCRIPT_VERSION_ANY_VALUE_PATTERN,
        string=file_content,
    )
    if not match_script_version:
        terminal.warning(
            f'Ignoring "{nasl_file}" because it is missing a script_version.'
        )
        return

    # get that date formatted correctly:
    # "2021-03-24T10:08:26+0000"
    correctly_formatted_version = f"{now:%Y-%m-%dT%H:%M:%S%z}"

    new_file_content = file_content.replace(
        match_script_version.group(0),
        script_version_template.format(date=correctly_formatted_version),
    )

    nasl_file.write_text(new_file_content, encoding=CURRENT_ENCODING)


def parse_args(args: Sequence[str] = None) -> Namespace:
    parser = ArgumentParser(
        description="Update script_version and last_modification tags"
    )
    what_group = parser.add_mutually_exclusive_group(required=True)
    what_group.add_argument(
        "--files",
        nargs="+",
        type=file_type_existing,
        help="List of files that should be updated",
    )
    what_group.add_argument(
        "--from-file",
        type=file_type_existing,
        help=(
            "Pass a file that contains a List of files "
            "containing paths to files, that should be "
            "updated. Files should be separated by newline."
        ),
    )
    return parser.parse_args(args)


def main() -> int:
    parsed_args = parse_args()
    terminal = ConsoleTerminal()

    if parsed_args.from_file:
        files = from_file(include_file=parsed_args.from_file, term=terminal)
    elif parsed_args.files:
        files: Iterable[Path] = parsed_args.files
    else:
        # will not happen
        sys.exit(1)

    for nasl_file in files:
        if nasl_file.suffix != ".nasl":
            terminal.warning(f'Skipping "{nasl_file}". Not a nasl file.')
            continue

        terminal.info(f'Updating "{nasl_file}"')
        update(nasl_file, terminal)
    return 0


if __name__ == "__main__":
    sys.exit(main())

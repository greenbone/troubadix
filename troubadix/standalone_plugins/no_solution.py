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

import re
import sys
from argparse import ArgumentParser, Namespace
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, List, Set

from pontos.terminal.terminal import ConsoleTerminal

from troubadix.helper import CURRENT_ENCODING
from troubadix.helper.patterns import ScriptTag, get_script_tag_pattern

SOLUTION_TYPE_NONE_AVAILABLE = "NoneAvailable"
CVSS_DETECTION_SCRIPT = "0.0"

SOLUTION_PATTERN = get_script_tag_pattern(ScriptTag.SOLUTION)
SOLUTION_DATE_PATTERN = re.compile(r"as\s+of\s*(?P<date>.+?)\.\s*", re.DOTALL)
SOLUTION_TYPE_PATTERN = get_script_tag_pattern(ScriptTag.SOLUTION_TYPE)
CREATION_DATE_PATTERN = get_script_tag_pattern(ScriptTag.CREATION_DATE)
CVSS_PATTERN = get_script_tag_pattern(ScriptTag.CVSS_BASE)

# Add the solutions date's here
SOLUTION_DATE_FORMATS = ["%d %B, %Y", "%d %b, %Y", "%Y/%m/%d"]
CREATION_DATE_FORMAT = "%Y-%m-%d"


def directory_type(string: str) -> Path:
    file_path = Path(string)
    if not file_path.is_dir():
        raise ValueError(f"{string} is not a directory.")
    return file_path


def parse_solution_date(date_string: str) -> datetime:
    """Convert date string to date trying different formats"""

    date_string = re.sub(
        r"(?P<date>.\d{1,2})(st|nd|rd|th)", r"\g<date>", date_string
    )

    for strptime in SOLUTION_DATE_FORMATS:
        try:
            date = datetime.strptime(date_string, strptime)

            return date
        except ValueError:
            pass

    return None


def parse_args() -> Namespace:
    parser = ArgumentParser(
        description="Check VTs for solution type NoneAvailable",
    )

    parser.add_argument(
        "-d",
        "--directory",
        dest="directory",
        type=directory_type,
        help="Specify the directory to scan for nasl scripts",
    )

    parser.add_argument(
        "-m",
        "--milestones",
        dest="milestones",
        help="Defines the milestones for which to report VTs "
        "without a solution for, in months",
        nargs="+",
        default=[12, 6, 1],
    )

    parser.add_argument(
        "-t",
        "--threshold",
        dest="threshold",
        type=int,
        default=12,
        help="The threshold after which to assume no solution "
        "will be provived anymore",
    )

    return parser.parse_args()


def check_skip_script(file_content: str) -> bool:
    solution_type = SOLUTION_TYPE_PATTERN.search(file_content)
    if (
        solution_type
        and solution_type.group("value") != SOLUTION_TYPE_NONE_AVAILABLE
    ):
        return True

    cvss = CVSS_PATTERN.search(file_content)
    if cvss and cvss.group("value") == CVSS_DETECTION_SCRIPT:
        return True

    return False


def check_no_solutions(
    files: Iterable[Path], milestones: List[int]
) -> Dict[str, Set]:
    summary = defaultdict(set)

    for nasl_file in files:
        content = nasl_file.read_text(encoding=CURRENT_ENCODING)

        if check_skip_script(content):
            continue

        solution_match = SOLUTION_PATTERN.search(content)
        if not solution_match:
            continue

        date_match = SOLUTION_DATE_PATTERN.search(solution_match.group("value"))
        if not date_match:
            continue

        solution_date = parse_solution_date(date_match.group("date"))

        if not solution_date:
            continue

        creation_match = CREATION_DATE_PATTERN.search(content)
        if not creation_match:
            continue

        creation_date = datetime.strptime(
            creation_match.group("value")[:10], CREATION_DATE_FORMAT
        )

        date_diff = solution_date - creation_date

        for milestone in milestones:
            # 365 / 12 = 30.4 ... This is as close as it will get
            delta = timedelta(days=milestone * 30.4)
            if date_diff >= delta:
                summary[milestone].add(nasl_file)
                break

    return summary


def report(
    summary: Dict[str, Set], milestones: List[int], threshold: int, root: Path
):
    term = ConsoleTerminal()
    total = sum(len(items) for _, items in summary.items())

    term.bold_info("Reported VTs with no available solution")
    with term.indent():
        milestone_str = ", ".join(str(milestone) for milestone in milestones)
        term.print(f"Milestones: {milestone_str} months")
        term.print(f"Expect no solution threshold: {threshold} months")
        term.print(f"Total VTs without solution: {total}")

    for milestone in milestones:

        if milestone >= threshold:
            term.bold_info(
                f"{len(summary[milestone])} VTs with no solution "
                f"for more than {milestone} month(s).\n"
                "No solution should be expected at this point. "
            )
        else:
            term.bold_info(
                f"{len(summary[milestone])} VTs with no solution for "
                f"more than {milestone} month(s)"
            )

        with term.indent():
            for vt in summary[milestone]:
                term.print(str(vt.relative_to(root)))


def main():
    root = Path.cwd()
    arguments = parse_args()

    if arguments.directory:
        root = arguments.directory
    else:
        root = Path.cwd()

    files = list(root.rglob("*.nasl"))

    milestones = sorted(arguments.milestones, reverse=True)

    summary = check_no_solutions(files, milestones)

    report(summary, milestones, arguments.threshold, root)


if __name__ == "__main__":
    sys.exit(main())

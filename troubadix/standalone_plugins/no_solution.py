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

import re
import sys
from argparse import ArgumentParser, Namespace
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, Optional, Tuple

from pontos.terminal.terminal import ConsoleTerminal

from troubadix.helper import CURRENT_ENCODING
from troubadix.helper.patterns import (
    ScriptTag,
    SpecialScriptTag,
    get_script_tag_pattern,
    get_special_script_tag_pattern,
)

SOLUTION_TYPE_NONE_AVAILABLE = "NoneAvailable"
CVSS_DETECTION_SCRIPT = "0.0"

SOLUTION_PATTERN = get_script_tag_pattern(ScriptTag.SOLUTION)
SOLUTION_DATE_PATTERN = re.compile(r"as\s+of\s*(?P<date>.+?)\.\s*", re.DOTALL)
SOLUTION_TYPE_PATTERN = get_script_tag_pattern(ScriptTag.SOLUTION_TYPE)
CREATION_DATE_PATTERN = get_script_tag_pattern(ScriptTag.CREATION_DATE)
CVSS_PATTERN = get_script_tag_pattern(ScriptTag.CVSS_BASE)
OID_PATTERN = get_special_script_tag_pattern(SpecialScriptTag.OID)

SOLUTION_DATE_FORMATS = ["%d %B, %Y", "%d %b, %Y", "%Y/%m/%d"]
CREATION_DATE_FORMAT = "%Y-%m-%d"

MONTH_AS_DAYS = 365 / 12


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
        description="Check VTs for solution type 'NoneAvailable'",
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
        "without a solution for, in months. VTs with no solution newer "
        "than the smallest milestone will not be reported.",
        nargs="+",
        type=int,
        default=[12, 6, 1],
    )

    parser.add_argument(
        "-t",
        "--threshold",
        dest="threshold",
        type=int,
        default=12,
        help="The threshold after which to assume no solution "
        "will be provided anymore",
    )

    parser.add_argument(
        "-s",
        "--snooze",
        dest="snooze",
        type=int,
        default=1,
        help="The duration, in months, to suppress reporting VTs after, based "
        "on the date stated in the solution text.",
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


def extract_tags(content: str) -> Optional[Tuple[str, datetime, datetime]]:
    solution_match = SOLUTION_PATTERN.search(content)
    if not solution_match:
        return None

    date_match = SOLUTION_DATE_PATTERN.search(solution_match.group("value"))
    if not date_match:
        return None

    solution_date = parse_solution_date(date_match.group("date"))
    if not solution_date:
        return None

    creation_match = CREATION_DATE_PATTERN.search(content)
    if not creation_match:
        return None

    creation_date = datetime.strptime(
        creation_match.group("value")[:10], CREATION_DATE_FORMAT
    )

    oid_match = OID_PATTERN.search(content)
    if not oid_match:
        return None

    oid = oid_match.group("value")

    return oid, creation_date, solution_date


def get_no_solution_vts(
    files: Iterable[Path],
) -> Iterable[Tuple[Path, str, datetime, datetime]]:
    file_contents = (
        (file, file.read_text(encoding=CURRENT_ENCODING)) for file in files
    )
    return (
        (file, *extract_tags(content))
        for file, content in file_contents
        if not check_skip_script(content)
    )


def check_no_solutions(
    files: Iterable[Tuple[Path, str, datetime, datetime]],
    milestones: list[int],
    snooze_duration: int,
) -> list[Tuple[int, list[Tuple[Path, str, datetime, datetime]]]]:
    last_milestone = milestones[-1]
    snooze_duration = timedelta(days=snooze_duration * MONTH_AS_DAYS)

    summary = defaultdict(list)

    for vt in get_no_solution_vts(files):
        _, _, creation_date, solution_date = vt

        milestone = next(
            (
                milestone
                for milestone in milestones
                if solution_date
                < creation_date + timedelta(days=milestone * MONTH_AS_DAYS)
                and milestone * MONTH_AS_DAYS
                <= (datetime.now() - creation_date).days
            ),
            None,
        )

        if solution_date > creation_date + timedelta(
            days=last_milestone * MONTH_AS_DAYS
        ):
            milestone = last_milestone

        if not milestone or (
            milestone == last_milestone
            and (datetime.now() - solution_date) < snooze_duration
        ):
            continue

        summary[milestone].append(vt)

    return sorted(
        ((milestone, vts) for milestone, vts in summary.items()),
        key=lambda tuple: tuple[0],
        reverse=True,
    )


def print_info(
    term: ConsoleTerminal,
    milestones: list[int],
    threshold: int,
    snooze: int,
    root: Path,
):
    term.bold_info("Report VTs with solution type 'NoneAvailable'")
    with term.indent():
        term.print(f"Root directory: {root}")
        milestone_str = ", ".join(str(milestone) for milestone in milestones)
        term.print(f"Milestones: {milestone_str} months")
        term.print(f"Expect no solution threshold: {threshold} months")
        term.print(f"Snooze duration: {snooze} months")


def print_report(
    term: ConsoleTerminal,
    summary: Iterable[Tuple[int, list[Tuple[Path, str, datetime, datetime]]]],
    threshold: int,
    root: Path,
    total: int,
):
    term.info(f"Total VTs without solution: {total}\n")

    for milestone, vts in summary:
        vts = sorted(vts)

        if milestone >= threshold:
            term.bold_info(
                f"{len(vts)} VTs with no solution "
                f"for more than {milestone} month(s).\n"
                "No solution should be expected at this point. "
            )
        else:
            term.bold_info(
                f"{len(vts)} VTs with no solution for "
                f"more than {milestone} month(s)"
            )

        for vt, oid, creation, solution in vts:
            term.info(str(vt.relative_to(root)))

            with term.indent():
                term.print(f"OID: {oid}")
                term.print(f"Created: {creation.strftime('%Y-%m-%d')}")
                term.print(
                    f"Last solution update: {solution.strftime('%Y-%m-%d')}"
                )

        term.print()


def main():
    try:
        arguments = parse_args()

        root = arguments.directory or Path.cwd()

        files = root.rglob("*.nasl")

        milestones = sorted(arguments.milestones)

        term = ConsoleTerminal()

        print_info(
            term, milestones, arguments.threshold, arguments.snooze, root
        )

        summary = check_no_solutions(files, milestones, arguments.snooze)

        found_vts = sum(len(entries) for _, entries in summary)

        print_report(term, summary, arguments.threshold, root, found_vts)

        sys.exit(1 if found_vts > 0 else 0)

    # pylint: disable=broad-except
    except Exception as e:
        print(f"troubadix-no-solution encountered an error: {e}")

        sys.exit(2)


if __name__ == "__main__":
    main()

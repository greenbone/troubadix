#  Copyright (c) 2022 Greenbone Networks GmbH
#
#  SPDX-License-Identifier: GPL-3.0-or-later
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
from typing import Iterator
from datetime import timedelta, datetime

from troubadix.helper import (
    CURRENT_ENCODING,
    ScriptTag,
    get_script_tag_pattern,
    get_path_from_root,
)
from troubadix.plugin import (
    LinterError,
    LinterResult,
    LinterWarning,
    FilesPlugin,
)


NO_SOLUTION_DATE_TOO_YOUNG = datetime.now() - timedelta(days=31)
NO_SOLUTION_DATE_TOO_OLDER_6_MONTH = datetime.now() - timedelta(days=186)
NO_SOLUTION_DATE_TOO_OLDER_1_YEAR = datetime.now() - timedelta(days=365)

# Add the solutions date's here
STRPTIMES = ["%d %B, %Y", "%Y/%m/%d"]


class CheckNoSolution(FilesPlugin):
    name = "check_no_solution"

    def run(self) -> Iterator[LinterResult]:
        """Run PRE_RUN_COLLECTOR."""

        total_missing_solutions = 0
        missing_solutions_younger_1_month = 0
        missing_solutions_older_than_6_months = 0
        missing_solutions_older_than_1_year = 0

        for nasl_file in self.context.nasl_files:
            file_name = get_path_from_root(nasl_file, self.context.root)
            content = nasl_file.read_text(encoding=CURRENT_ENCODING)
            solution_match = get_script_tag_pattern(ScriptTag.SOLUTION).search(
                content
            )

            if solution_match:
                date_match = re.compile(
                    r"as\s+of\s*(?P<date>.+?)\.\s*", re.DOTALL
                ).search(solution_match.group("value"))
            else:
                yield LinterError(f"{file_name}: No Solution tag found.")
                continue

            # total number of missing solutions
            if date_match:
                total_missing_solutions += 1
            else:
                continue

            no_solution_since = parse_date(date_match.group("date"))

            # no solution and older than 1 year
            if no_solution_since <= NO_SOLUTION_DATE_TOO_OLDER_1_YEAR:
                missing_solutions_older_than_1_year += 1
                yield LinterWarning(
                    f"{file_name}: Missing solution, older than 1 year."
                )
                continue

            # no solution and older than 6 months
            if no_solution_since <= NO_SOLUTION_DATE_TOO_OLDER_6_MONTH:
                missing_solutions_older_than_6_months += 1
                yield LinterWarning(
                    f"{file_name}: Missing solution, older than 6 months."
                )
                continue

            # no solution and younger than 31 days
            if no_solution_since >= NO_SOLUTION_DATE_TOO_YOUNG:
                missing_solutions_younger_1_month += 1
                yield LinterWarning(
                    f"{file_name}: Missing solution, but younger than 31 days."
                )

        if total_missing_solutions > 0:
            yield LinterWarning(
                "total missing solutions:"
                f" {total_missing_solutions}\n"
                "missing solutions younger 1 month:"
                f" {missing_solutions_younger_1_month}\n"
                "missing solutions older than 6 months:"
                f" {missing_solutions_older_than_6_months}\n"
                "missing solutions older than 1 year:"
                f" {missing_solutions_older_than_1_year}\n"
            )


def parse_date(date_string: str) -> datetime:
    """Convert date string to date trying different formats"""

    date_string = re.sub(r"(st|nd|rd|th)", "", date_string)

    for strptime in STRPTIMES:
        try:
            date = datetime.strptime(date_string, strptime)

            return date
        except ValueError:
            pass

    return None

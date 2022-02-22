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
import subprocess
from pathlib import Path
from typing import Iterator, List

from naslinter.plugin import GitCommitRangePlugin, LinterError, LinterResult


def subprocess_cmd(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    proc_stdout = process.communicate()[0].strip()
    return proc_stdout


class CheckChangedOid(GitCommitRangePlugin):
    name = "check_changed_oid"

    @staticmethod
    def run(nasl_file: Path, commit_range: List[str]) -> Iterator[LinterResult]:
        """The script checks (via git diff) if the passed VT has changed the
        OID in the following tag:

        - script_oid("1.2.3");

        This is only allowed in rare cases (e.g. a single VT was split into
        two VTs).

        Args:
            nasl_file: The VT that shall be checked
            commit_range: The git commit range to be checked (if passed via
                            --commit-range of the "master" script)
        """
        # Does only apply to NASL files.
        if not nasl_file.suffix == ".nasl":
            return

        if len(commit_range) == 1:
            git_commit_range = commit_range[0]
        elif len(commit_range) == 2:
            git_commit_range = commit_range[0] + ".." + commit_range[1]
        else:
            yield LinterError(
                "--commit-range must be either a single branch, commit or a "
                "range of commits/branches."
            )
            return
        # nb: diff HEAD (passed via the commit_range parameter) only shows
        # staged and un-staged changes since the last commit. It will miss if
        # the OID was changed in an earlier commit but that is currently
        # accepted.
        text = subprocess_cmd(
            "git -c color.status=false --no-pager diff "
            + git_commit_range
            + " "
            + nasl_file
        ).decode("latin-1")

        # if the script_oid was changed something like e.g. the following
        # might show up in the git output:
        #
        # -  script_oid("1.3.6.1.4.1.25623.1.0.109800");
        # *snip*
        # +  script_oid("1.3.6.1.4.1.25623.1.0.150221");
        #
        # Note: It might happen that the script_oid just get moved to a
        # different location like e.g.:
        #
        # -  script_oid("1.3.6.1.4.1.25623.1.0.109800");
        # *snip*
        # +  script_oid("1.3.6.1.4.1.25623.1.0.109800");
        #
        # which shouldn't trigger any error.

        oid_added = re.search(
            r'^\+\s*script_oid\s*\(\s*["\']([0-9.]+)["\']\s*\)\s*;',
            text,
            re.MULTILINE,
        )
        if oid_added is None or oid_added.group(1) is None:
            return

        oid_removed = re.search(
            r'^-\s*script_oid\s*\(\s*["\']([0-9.]+)["\']\s*\)\s*;',
            text,
            re.MULTILINE,
        )
        if oid_removed is None or oid_removed.group(1) is None:
            return

        if oid_added.group(1) != oid_removed.group(1):
            yield LinterError(
                f"OID of VT '{str(nasl_file)}' was changed. This "
                "is only allowed in rare cases (e.g. a single VT "
                "was split into two VTs)."
                + "\n"
                + oid_added.group(0)
                + "\n"
                + oid_removed.group(0)
            )
            return

        return

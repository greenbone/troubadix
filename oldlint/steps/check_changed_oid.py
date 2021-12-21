#!/usr/bin/env python3

import re
import sys
import subprocess


def subprocess_cmd(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    proc_stdout = process.communicate()[0].strip()
    return proc_stdout


def run(file, commit_range):
    """The script checks (via git diff) if the passed VT has changed the OID in the following tag:

    - script_oid("1.2.3");

    This is only allowed in rare cases (e.g. a single VT was split into two VTs).

    Args:
        file: The VT that shall be checked
        commit_range: The git commit range to be checked (if passed via --commit-range of the "master" script)

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message
    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    # nb: diff HEAD (passed via the commit_range parameter) only shows staged and unstaged changes since the
    # last commit. It will miss if the OID was changed in an earlier commit but that is currently accepted.
    text = subprocess_cmd(
        "git -c color.status=false --no-pager diff " + commit_range + " " + file
    ).decode("latin-1")

    # if the script_oid was changed something like e.g. the following might show up in the git output:
    #
    # -  script_oid("1.3.6.1.4.1.25623.1.0.109800");
    # *snip*
    # +  script_oid("1.3.6.1.4.1.25623.1.0.150221");
    #
    # Note: It might happen that the script_oid just get moved to a different location like e.g.:
    #
    # -  script_oid("1.3.6.1.4.1.25623.1.0.109800");
    # *snip*
    # +  script_oid("1.3.6.1.4.1.25623.1.0.109800");
    #
    # which shouldn't trigger any error.

    oid_added = re.search(
        "^\+\s*script_oid\s*\(\s*[\"']([0-9.]+)[\"']\s*\)\s*;",
        text,
        re.MULTILINE,
    )
    if oid_added is None or oid_added.group(1) is None:
        return (0,)

    oid_removed = re.search(
        "^-\s*script_oid\s*\(\s*[\"']([0-9.]+)[\"']\s*\)\s*;",
        text,
        re.MULTILINE,
    )
    if oid_removed is None or oid_removed.group(1) is None:
        return (0,)

    if oid_added.group(1) != oid_removed.group(1):
        report = (
            "OID of VT '"
            + str(file)
            + "' was changed. This is only allowed in rare cases (e.g. a single VT was split into two VTs)."
        )
        report += "\n" + oid_added.group(0)
        report += "\n" + oid_removed.group(0)
        return -1, report

    return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = run(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report("VT(s) with changed OID(s) found", error)
        sys.exit(1)

    sys.exit(0)

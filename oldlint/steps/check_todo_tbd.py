#!/usr/bin/env python3

import re, os, sys


def run(file):
    """This steps checks if the VT contains a TBD, TODO or @todo item.

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
                1 => Success, with debug messages

    """

    report = ""

    with open(file, "rt", encoding="latin-1") as f:
        for line in f:
            tbd_todo = re.search("##? ?(TODO|TBD|@todo):?", line)
            if tbd_todo is not None:
                report += "\n" + line.strip() + "\n"

    if len(report) > 0:
        report = (
            "VT '" + str(file) + "' contains a TBD, TODO or @todo item which "
            "should be checked at the following lines:\n" + report
        )
        return 1, report
    return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = run(file)
            if test[0] == 1:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report(
            "Files contain a TBD, TODO or @todo item which should be checked",
            error,
        )
        sys.exit(1)

    sys.exit(0)

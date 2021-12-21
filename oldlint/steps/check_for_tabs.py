#!/usr/bin/env python3

import re
import sys


def is_using_tabs(file):
    """This script checks if a VT is using one or more tabs instead of spaces.

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message

    """

    text = open(file, encoding="latin-1").read()

    tabs_found = False
    tab_matches = re.finditer("\t+", text)

    if tab_matches is not None:
        for tab_match in tab_matches:
            if tab_match is not None and tab_match.group(0) is not None:
                tabs_found = True

    if tabs_found:
        return (
            -1,
            "The VT '"
            + str(file)
            + "' is using one or more tabs instead of spaces!",
        )

    return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = is_using_tabs(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report("VTs using one or more tabs instead of spaces", error)
        sys.exit(1)

    sys.exit(0)

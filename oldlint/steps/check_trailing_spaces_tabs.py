#!/usr/bin/env python3

import re
import sys


def has_trailing_spaces_tabs(file):
    """This script checks if a VT is using one or more trailing whitespaces or tabs.

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message

    """

    text = open(file, encoding="latin-1").read()

    spaces_tabs_found = False
    spaces_tabs_matches = re.finditer("[\t ]+$", text)

    if spaces_tabs_matches is not None:
        for spaces_tabs_match in spaces_tabs_matches:
            if (
                spaces_tabs_match is not None
                and spaces_tabs_match.group(0) is not None
            ):
                spaces_tabs_found = True

    if spaces_tabs_found:
        return (
            -1,
            "The VT '"
            + str(file)
            + "' has one or more trailing newlines and/or tabs!",
        )

    return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = has_trailing_spaces_tabs(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report(
            "VTs having one or more trailing newlines and/or tabs", error
        )
        sys.exit(1)

    sys.exit(0)

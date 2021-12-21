#!/usr/bin/env python3

import re
import sys


def is_category_correct(file):
    """Checks the passed VT for the existence / validity of its script category with the help of regular expression.
    An error will be thrown if the VT does not contain of a script_category at all or if the used script_category is misspelled or invalid.

    Args:
        file: The VT that shall be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message
    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    text = open(file, encoding="latin-1").read()
    match = re.search("script_category\(([^)]+)\);", text)

    if match is None or match.group(1) is None:
        return -1, "VT '" + str(file) + "' is missing a script_category!"

    category = match.group(1)

    # List of valid script categories: https://github.com/greenbone/openvas-scanner/blob/master/misc/nvt_categories.h
    valid_categories = [
        "ACT_END",
        "ACT_FLOOD",
        "ACT_KILL_HOST",
        "ACT_DENIAL",
        "ACT_DESTRUCTIVE_ATTACK",
        "ACT_MIXED_ATTACK",
        "ACT_ATTACK",
        "ACT_GATHER_INFO",
        "ACT_SETTINGS",
        "ACT_SCANNER",
        "ACT_INIT",
    ]

    for valid_category in valid_categories:
        if category == valid_category:
            return (0,)

    return (
        -1,
        "VT '"
        + str(file)
        + "' is using an invalid or misspelled script category!",
    )


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = is_category_correct(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report(
            "VTs with missing or malformed script_category", error
        )
        sys.exit(1)

    sys.exit(0)

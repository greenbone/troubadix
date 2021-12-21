#!/usr/bin/env python3

import re
import sys


def has_misplaced_compare_in_if(file):
    """This script checks the passed VT/Include if it is using a misplaced compare within an if() call like e.g.:

        if( variable >< "text" ) {}
        if( variable >< 'text' ) {}
        if( variable >!< "text" ) {}
        if( variable >!< 'text' ) {}

        instead of:

        if( "text" >< variable ) {}
        if( "text" >!< variable ) {}

    Args:
        file: The VT/Include that is going to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message

    """

    text = open(file, encoding="latin-1").read()

    # TODO: Find a better way to parse if calls as this would miss something like e.g.:
    #
    # if((foo =~ "bar || bar =~ "foo") || foobar = "foo"){}
    #
    # nb: We can't use { as an ending delimiter as there could be also something like e.g.:
    #
    # if((foo =~ "bar || bar =~ "foo") || foobar = "foo")
    #   bar = "foo"; (no ending {)
    if_matches = re.finditer(
        "^\s*(if|}?\s*else if)\s*\(([^)]+)", text, re.MULTILINE
    )
    if if_matches is None:
        return (0,)

    misplaced_compare_found = False
    misplaced_compare_report = (
        "VT/Include '"
        + str(file)
        + "' is using a misplaced compare within an if() call in the following line(s):\n"
    )

    for if_match in if_matches:
        if if_match is not None and if_match.group(1) is not None:

            misplaced_compare_match = re.search(
                "((if|}?\s*else if)\s*\(\s*?|\|\|\s*|&&\s*)[a-zA-Z_]+\s*>\!?<\s*(\"|')",
                if_match.group(0),
            )
            if (
                misplaced_compare_match is not None
                and misplaced_compare_match.group(1) is not None
            ):
                misplaced_compare_report = (
                    misplaced_compare_report + if_match.group(0) + "\n"
                )
                misplaced_compare_found = True

    if misplaced_compare_found:
        return -1, misplaced_compare_report

    return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if not files:
        sys.exit(0)

    for file in files:
        test = has_misplaced_compare_in_if(file)
        if test[0] == -1:
            error.append(file)

    if len(error) > 0:
        ci_helpers.report(
            "Files having a misplaced compare within an if() call", error
        )
        sys.exit(-1)

    sys.exit(0)

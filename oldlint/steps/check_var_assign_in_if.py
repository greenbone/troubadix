#!/usr/bin/env python3

import re
import sys


def has_var_assign_in_if(file):
    """This script checks the passed VT/Include if it is using a variable assignment within an if() call like e.g.:

        if( variable = "text" ) {}

        instead of:

        if( variable =~ "text" ) {}
        if( variable == "text" ) {}

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

    var_assign_found = False
    var_assign_report = (
        "VT/Include '"
        + str(file)
        + "' is using a variable assignment within an if() call in the following line(s):\n"
    )

    for if_match in if_matches:
        if if_match is not None and if_match.group(1) is not None:

            var_assign_match = re.search(
                "((if|}?\s*else if)\s*\(\s*?|\|\|\s*|&&\s*)[a-zA-Z_]+\s*=\s*(\"|'|TRUE|0|1)",
                if_match.group(0),
            )
            if (
                var_assign_match is not None
                and var_assign_match.group(1) is not None
            ):

                # nb: Can't be fixed because it would mean a change of a default behavior.
                if (
                    "policy_file_checksums_win.nasl" in file
                    and "install = " in if_match.group(0)
                ):
                    continue

                var_assign_report = var_assign_report + if_match.group(0) + "\n"
                var_assign_found = True

    if var_assign_found:
        return -1, var_assign_report

    return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if not files:
        sys.exit(0)

    for file in files:
        test = has_var_assign_in_if(file)
        if test[0] == -1:
            error.append(file)

    if len(error) > 0:
        ci_helpers.report(
            "Files using an variable assignment within an if() call", error
        )
        sys.exit(-1)

    sys.exit(0)

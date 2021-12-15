#!/usr/bin/env python3

import re
from pathlib import Path
from typing import List

ENCODING = "latin-1"


def has_var_assign_in_if(file: Path) -> str:
    """This script checks the passed VT/Include if it is using
       a variable assignment within an if() call like e.g.:

        if( variable = "content" ) {}

        instead of:

        if( variable =~ "content" ) {}
        if( variable == "content" ) {}

    Args:
        file: The VT/Include that is going to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message

    """

    content = file.read_text(encoding=ENCODING)

    # TO DO: Find a better way to parse if calls as this would
    # miss something like e.g.:
    #
    # if((foo =~ "bar" || bar =~ "foo") || foobar = "foo"){}
    #
    # nb: We can't use { as an ending delimiter as there could
    # be also something like e.g.:
    #
    # if((foo =~ "bar || bar =~ "foo") || foobar = "foo")
    #   bar = "foo"; (no ending {)
    matches = re.finditer(
        r"^\s*(if|}?\s*else if)\s*\(([^)]+)", content, re.MULTILINE
    )
    if matches is None:
        return (0,)

    lint_error = False
    output = (
        f"VT/Include '{str(file.name)}' is using a variable assignment"
        " within an if() call in the following line(s):\n"
    )

    for match in matches:
        if match is not None and match.group(1) is not None:

            var_assign_match = re.search(
                r"((if|}?\s*else if)\s*\(\s*?|\|{2}\s*|&{2}\s*)"
                r'[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*("|\'|TRUE|0|1)',
                match.group(0),
            )
            if (
                var_assign_match is not None
                and var_assign_match.group(1) is not None
            ):
                # nb: Can't be fixed because it would mean a change
                # of a default behavior.
                if (
                    "policy_file_checksums_win.nasl" in file.name
                    and "install = " in match.group(0)
                ):
                    continue

                output = f"{output} {match.group(0)}\n"
                lint_error = True

    if lint_error:
        return -1, output

    return (0,)


def check_files(files: List[Path]) -> None:
    for file in files:
        has_var_assign_in_if(file)


# if __name__ == "__main__":
#     import ci_helpers

#     error = []
#     files = ci_helpers.list_modified_files()
#     if not files:
#         sys.exit(0)

#     for file in files:
#         test = has_var_assign_in_if(file)
#         if test[0] == -1:
#             error.append(file)

#     if len(error) > 0:
#         ci_helpers.report(
#             "Files using an variable assignment within an if() call",
#             error,
#         )
#         sys.exit(-1)

#     sys.exit(0)

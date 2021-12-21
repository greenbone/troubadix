#!/usr/bin/env python3

import re
import sys


def has_missing_desc_exit(file):
    """This script checks if a VT is missing an 'exit(0);' within the description block like

    if(description) {
      *tags*
    }

    which should be the following instead:

    if(description) {
      *tags*
      exit(0);
    }

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
                1 => Success, with debug message
               -1 => Error, with error message

    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    text = open(file, encoding="latin-1").read()

    match = re.search(
        "^if *\( *description *\)\s*\{(.*?)(?=^})",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if match and match.group(1):
        submatch = re.search(
            "^ *exit *\( *0 *\) *;", match.group(1), re.MULTILINE
        )
        if submatch is None or submatch.group(0) is None:
            return (
                -1,
                "No mandatory exit(0); found in the description block of VT '"
                + str(file),
            )

        return (0,)

    return 1, "No description block extracted/found in VT '" + str(file)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = has_missing_desc_exit(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report(
            "VTs missing exit() function in the description block", error
        )
        sys.exit(1)

    sys.exit(0)

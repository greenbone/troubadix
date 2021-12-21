#!/usr/bin/env python3

import re
import sys


def run(file):
    """The script checks if the passed VT has a correct syntax of the following two tags:

    - script_version();
    - script_tag(name:"last_modification", value:"");

    An error will be thrown if the syntax of those two tags does not match the requirements.

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
    report = ""

    # script_version("2019-03-21T12:19:01+0000");")
    match_ver_modified = re.search(
        'script_version\("[0-9\-\:\+T]{24}"\);', text
    )

    if match_ver_modified is None:
        report += (
            "VT '"
            + str(file)
            + "' is missing script_version(); or is using a wrong syntax."
            + "\n"
        )

    # script_tag(name:"last_modification", value:"2019-03-21 12:19:01 +0000 (Thu, 21 Mar 2019)");
    match_last_modified = re.search(
        'script_tag\(name:"last_modification",\svalue:"[A-Za-z0-9\:\-\+\,\s\(\)]{44}"\);',
        text,
    )

    if match_last_modified is None:
        report += (
            "VT '"
            + str(file)
            + '\' is missing script_tag(name:"last_modification" or is using a wrong syntax.'
            + "\n"
        )

    if len(report) > 0:
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
        ci_helpers.report(
            "VTs with missing or malformed script_version or last_modification tag",
            error,
        )
        sys.exit(1)

    sys.exit(0)

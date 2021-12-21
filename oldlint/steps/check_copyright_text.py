#!/usr/bin/env python3

import re, os, sys


def run(file):
    """This step checks a VT for the correct use of the copyright text.

    Prior to this step, most VTs are using "This script is Copyright (C) [...]",
    however the introductory text ("This script is") is to be discarded from now on.

    In addition it will also report any occurrence of the following outdated text
    pattern:

    # Text descriptions are largely excerpted from the referenced
    # advisory, and are Copyright (C) of their respective author(s)

    or:

    # Text descriptions are largely excerpted from the referenced
    # advisory, and are Copyright (C) the respective author(s)

    or:

    # Text descriptions are largely excerpted from the referenced
    # advisory, and are Copyright (C) the respective author(s)

    or:

    # Some text descriptions might be excerpted from the referenced
    # advisories, and are Copyright (C) by the respective right holder(s)

    which should be the following from now on:

    # Some text descriptions might be excerpted from (a) referenced
    # source(s), and are Copyright (C) by the respective right holder(s).

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message

    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    report = ""

    text = open(file, encoding="latin-1").read()

    if not re.search('script_copyright\("Copyright \(C\) [0-9]{4}', text):
        report += (
            "The VT '"
            + str(file)
            + "' is using an incorrect syntax for its copyright statement. Please start (EXACTLY) with:\n\n"
            "'script_copyright(\"Copyright (C)' followed by the year (matching the one in creation_date) and the author/company.\n"
        )

    if re.search(
        "^# (Text descriptions are largely excerpted from the referenced\n# advisory, and are Copyright \([cC]\) (of )?(the |their )respective author\(s\)|Some text descriptions might be excerpted from the referenced\n# advisories, and are Copyright \(C\) by the respective right holder\(s\))",
        text,
        re.MULTILINE,
    ):
        if len(report) > 0:
            report += "\n"
        report += (
            "The VT '"
            + str(file)
            + "' is using an incorrect copyright statement. Please use (EXACTLY):\n\n"
            "# Some text descriptions might be excerpted from (a) referenced\n# source(s), and are Copyright (C) by the respective right holder(s).\n"
        )

    if len(report) > 0:
        return -1, report

    return (0,)


if __name__ == "__main__":
    import ci_helpers

    exit_error = False

    copyright_text_errors = []

    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = run(file)
            if test[0] != 0:
                copyright_text_errors.append(file)
    else:
        sys.exit(0)

    if len(copyright_text_errors) > 0:
        ci_helpers.report(
            "VTs having a wrong script_copyright() text", copyright_text_errors
        )
        exit_error = True

    if exit_error:
        sys.exit(1)

    sys.exit(0)

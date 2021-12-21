#!/usr/bin/env python3

import re
import sys


def is_cvss_format_correct(file):
    """This script checks the passed VT for the existence/format of its CVSS base vector and value with the help of regular expression.
    An error will be thrown if CVSS tags are being incorrectly formatted or missing.

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message

    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    text = open(file, encoding="latin-1").read()
    score_match = re.search(
        '(script_tag\(\s*name\s*:\s*"cvss_base"\s*,\s*value\s*:\s*")\d{1,2}\.\d"\s*\)\s*;',
        text,
    )
    vector_match = re.search(
        '(script_tag\(\s*name\s*:\s*"cvss_base_vector"\s*,\s*value\s*:\s*")AV:[LAN]\/AC:[HML]\/Au:[NSM]\/C:[NPC]\/I:[NPC]\/A:[NPC]"\s*\)\s*;',
        text,
    )

    if (
        score_match is None
        or vector_match is None
        or score_match.group(0) is None
        or vector_match.group(0) is None
    ):
        return (
            -1,
            "VT '"
            + str(file)
            + "' is missing CVSS tags or uses invalid formats for CVSS Score/Vector!",
        )
    return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = is_cvss_format_correct(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report(
            "VTs with malformed or missing CVSS base vector", error
        )
        sys.exit(1)

    sys.exit(0)

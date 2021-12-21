#!/usr/bin/env python3

import re
import sys


def is_solution_type_correct(file):
    """This script checks the passed VT for the existence/format of its solution_type with the help of regular expression.
    An error will be thrown if the VT does not contain a solution_type at all or of the solution_type contains an invalid value.

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

    has_severity = True

    # don't need to check detection scripts since they don't contain a solution type.
    # all detection scripts have a cvss of 0.0
    cvss_detect = re.search(
        'script_tag\s*\(name\s*:\s*"cvss_base",\s*value:\s*"(\d{1,2}\.\d)"',
        text,
    )
    if cvss_detect is not None and cvss_detect.group(1) == "0.0":
        has_severity = False

    values = (
        "Workaround",
        "Mitigation",
        "VendorFix",
        "NoneAvailable",
        "WillNotFix",
    )

    # example: script_tag( name: "solution_type", value: "VendorFix );
    match_result = re.search(
        'script_tag\s*\(name\s*\:\s*"(solution_type)"\s*\,\s*value\s*\:\s*"([a-zA-Z]+)"\s*\)\s*\;',
        text,
    )

    if has_severity:
        if match_result is None or match_result.group(1) is None:
            return (
                -1,
                "VT '" + str(file) + "' does not contain a solution_type.",
            )
    if match_result is not None and match_result.group(2) not in values:
        return (
            -1,
            "VT '"
            + str(file)
            + "' does not contain a valid solution_type 'value'!",
        )
    return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = is_solution_type_correct(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report("VTs with missing or invalid solution_type", error)
        sys.exit(1)

    sys.exit(0)

#!/usr/bin/env python3

import re
import sys


def is_using_log_message_with_severity(file):
    """This script checks the passed VT if is using a log_message and having a severity (CVSS score)
        assigned which is an error / debugging leftover in most cases.

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
                1 => Success, with debug messages
               -1 => Error, with error message

    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    # Policy VTs might use both, security_message and log_message
    if "Policy/" in file:
        return (0,)

    text = open(file, encoding="latin-1").read()

    # don't need to check detection scripts since they are for sure using a log_message.
    # all detection scripts have a cvss of 0.0
    cvss_detect = re.search(
        'script_tag\s*\(name\s*:\s*"cvss_base",\s*value:\s*"(\d{1,2}\.\d)"',
        text,
    )
    if cvss_detect is not None and cvss_detect.group(1) == "0.0":
        return (0,)

    log_match = re.search(
        ".*(log_message[\s]*\([^)]+\)[\s]*;)", text, re.MULTILINE
    )

    if log_match:
        return (
            1,
            "VT '"
            + str(file)
            + "' is using a log_message in a VT with a severity",
        )
    else:
        return (0,)


if __name__ == "__main__":
    import ci_helpers

    error, debug = [], []
    files = ci_helpers.list_modified_files()
    if not files:
        sys.exit(0)

    for file in files:
        test = is_using_log_message_with_severity(file)
        if test[0] == -1:
            error.append(file)
        if test[0] == 1:
            debug.append(file)

    if len(debug) > 0:
        ci_helpers.report(
            "Files using a log_message in a VT with a severity", debug
        )

    # if len(error) > 0:
    #    ci_helpers.report("Files using a log_message in a VT with a severity", error)
    #    sys.exit(-1)

    sys.exit(0)

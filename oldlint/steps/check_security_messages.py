#!/usr/bin/env python3

import re
import sys


def run(file):
    """This script checks the passed VT if is using a security_message and having no severity (CVSS score)
        assigned which is an error / debugging leftover in most cases.

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message

    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    # Policy VTs might use both, security_message and log_message
    if "Policy/" in file or "PCIDSS/" in file or "GSHB/" in file:
        return (0,)

    text = open(file, encoding="latin-1").read()

    # don't need to check VTs having having a severity (which are for sure using a security_message)
    # or no cvss_base (which shouldn't happen and is checked in a separate step) included at all.
    cvss_detect = re.search(
        'script_tag\s*\(name\s*:\s*"cvss_base"\s*,\s*value\s*:\s*"(\d{1,2}\.\d)"',
        text,
    )
    if cvss_detect is None or cvss_detect.group(1) != "0.0":
        return (0,)

    sec_match = re.search(
        ".*(security_message\s*\([^)]+\)\s*;)", text, re.MULTILINE
    )

    if sec_match:
        return (
            -1,
            "VT '"
            + str(file)
            + "' is using a security_message in a VT without severity",
        )
    else:
        return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if not files:
        sys.exit(0)

    for file in files:
        test = run(file)
        if test[0] == -1:
            error.append(file)

    if len(error) > 0:
        ci_helpers.report(
            "Files using a security_message in a VT without severity", error
        )
        sys.exit(-1)

    sys.exit(0)

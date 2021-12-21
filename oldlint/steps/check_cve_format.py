#!/usr/bin/env python3

import re
import datetime
import sys


def is_cve_format_correct(file):
    """This script checks the passed VT for the existence/format of its CVE's with the help of regular expression.
    An error will be thrown if a CVE is missing, an invalid CVE format is being used, the CVE is incorrectly formatted
    or a CVE is referenced multiple times.

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

    current_year = datetime.datetime.now().year
    text = open(file, encoding="latin-1").read()

    # don't need to check detection scripts since they don't refer to CVEs.
    # all detection scripts have a cvss of 0.0
    cvss_detect = re.search(
        'script_tag\s*\(name\s*:\s*"cvss_base",\s*value:\s*"(\d{1,2}\.\d)"',
        text,
    )
    if cvss_detect is not None and cvss_detect.group(1) == "0.0":
        return (0,)

    match_result = re.search(
        "(?<=script_cve_id)[^;]+", text
    )  # ("CVE-2017-2750");
    if match_result is None or match_result.group(0) is None:
        return 1, "VT '" + str(file) + "' does not refer to any CVEs."

    found_cves = []
    matches = match_result.group(0).split(",")
    for match in matches:
        result = re.search('"CVE-\d{4}-\d{4,7}"', match)
        if result is None or result.group(0) is None:
            return -1, "VT '" + str(file) + "' uses an invalid CVE format!"

        cve = result.group(0)

        if len(cve) > 15 and cve[10] == "0":
            return (
                -1,
                "The last group of CVE digits of VT'"
                + str(file)
                + "' must not start with a 0 if there are more than 4 digits!",
            )

        year = cve.split("-")
        if not 1999 <= int(year[1]) <= current_year:
            return (
                -1,
                "VT '" + str(file) + "' uses an invalid year in CVE format!",
            )

        if cve in found_cves:
            return (
                -1,
                "VT '"
                + str(file)
                + "' is using CVE "
                + str(cve)
                + " multiple times!",
            )

        found_cves.append(cve)

    return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    debug = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = is_cve_format_correct(file)
            if test[0] == -1:
                error.append(file)
            if test[0] == 1:
                debug.append(file)
    else:
        sys.exit(0)

    if len(debug) > 0:
        ci_helpers.report("VTs not referring to any CVE", debug)

    if len(error) > 0:
        ci_helpers.report("VTs with malformed or duplicated CVE(s)", error)
        sys.exit(1)

    sys.exit(0)

#!/usr/bin/env python3

import re
import sys


def has_missing_solution_tag(file):
    """This script checks if a VT is using a:

    script_tag(name:"solution_type", value:"");

    tag but missing a:

    script_tag(name:"solution", value:"");

    tag within the description block.

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message

    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    # We don't want to touch the metadata of this older VTs...
    if "nmap_nse/" in file:
        return (0,)

    text = open(file, encoding="latin-1").read()

    # Not all VTs have/require a solution_type text
    if "solution_type" not in text:
        return (0,)

    # Avoid unnecessary message against deprecated VTs.
    ign = re.search(
        'script_tag\s*\(\s*name\s*:\s*"deprecated"\s*,\s*value\s*:\s*TRUE\s*\)\s*;',
        text,
    )
    if ign is not None:
        return (0,)

    match = re.search(
        "\s*script_tag\(\s*name\s*:\s*[\"']solution_type[\"']\s*,\s*value\s*:\s*[\"'].+[\"']\s*\)\s*;",
        text,
    )
    if match and match.group(0):
        submatch = re.search(
            "^\s*script_tag\(\s*name\s*:\s*[\"']solution[\"']\s*,\s*value\s*:\s*[\"'].+[\"']\s*\)\s*;",
            text,
            re.MULTILINE | re.DOTALL,
        )
        if submatch is None or submatch.group(0) is None:
            return (
                -1,
                "'solution_type' script_tag but no 'solution' script_tag found in the description block of VT '"
                + str(file),
            )

    return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = has_missing_solution_tag(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report(
            "VTs using a 'solution_type' script_tag but no 'solution' script_tag in the description block",
            error,
        )
        sys.exit(1)

    sys.exit(0)

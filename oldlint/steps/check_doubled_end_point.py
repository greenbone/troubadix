#!/usr/bin/env python3

import re
import sys


def run(file):
    """This script checks if a VT is using one or more doubled end point in a script_tag like e.g.:

    script_tag(name:"insight", value:"My insight..");

    or:

    script_tag(name:"insight", value:"My insight.
    .");

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

    doubled_end_points = ""

    tag_matches = re.finditer(
        '(script_tag\(name\s*:\s*"(summary|impact|affected|insight|vuldetect|solution)"\s*,\s*value\s*:\s*")([^"]+"\s*\)\s*;)',
        text,
        re.MULTILINE,
    )

    if tag_matches is not None:
        for tag_match in tag_matches:
            if tag_match is not None and tag_match.group(3) is not None:
                doubled_end_points_match = re.search(
                    '.*\.\s*\."\s*\)\s*;', tag_match.group(3), re.MULTILINE
                )
                if (
                    doubled_end_points_match is not None
                    and doubled_end_points_match.group(0) is not None
                ):

                    # Valid string used in a few VTs.
                    if 'and much more...");' in doubled_end_points_match.group(
                        0
                    ):
                        continue

                    doubled_end_points += (
                        "\n\t"
                        + tag_match.group(0).partition(",")[0]
                        + ", hit: "
                        + doubled_end_points_match.group(0)
                    )

    if len(doubled_end_points) > 0:
        return (
            -1,
            "The following script_tags of VT '"
            + str(file)
            + "' are ending with two or more end points:"
            + str(doubled_end_points)
            + "\n",
        )

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
            "VTs having a script_tag ending with more then one end point", error
        )
        sys.exit(1)

    sys.exit(0)

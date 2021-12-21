#!/usr/bin/env python3

import re, sys
from datetime import datetime, date


def is_creation_date_correct(file):
    """This script checks the existence and the correct format of the VT's creation_date via datetime functions.
    Furthermore it is being checked whether both dates inside the creation_date are equal.
    An error will be thrown if the creation_date is missing, incorrectly formatted, consists of two different dates
    or contains the wrong day of the week.

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message

    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    with open(file, "r", encoding="latin-1") as f:
        for row in f:
            if "creation_date" in row:
                expre = re.search('value\s*:\s*"(.*)"', row)
                if expre:
                    crdate = expre.group(1)
                    # Example: "2017-11-29 13:56:41 +0100 (Wed, 29 Nov 2017)"
                    if crdate:
                        try:
                            values = re.match("([^\(]+)\(([^\)]+)", crdate)
                            date_left = datetime.strptime(
                                values.group(1).strip(), "%Y-%m-%d %H:%M:%S %z"
                            )  # 2017-11-29 13:56:41 +0100 (error if no timezone)
                            date_right = datetime.strptime(
                                values.group(2).strip(), "%a, %d %b %Y"
                            )  # Wed, 29 Nov 2017
                            if date_left.date() != date_right.date():
                                return (
                                    -1,
                                    "The creation_date of VT '"
                                    + str(file)
                                    + "' consists of two different dates.",
                                )
                            if values.group(2).strip()[
                                :3
                            ] != date_right.strftime("%a"):
                                return (
                                    -1,
                                    "Wrong day of week in VT '"
                                    + str(file)
                                    + "'. Please change it from '"
                                    + values.group(2).strip()[:3]
                                    + "' to '"
                                    + str(date_left.strftime("%a"))
                                    + "'.",
                                )
                            if len(crdate) != 44:
                                return (
                                    -1,
                                    "Incorrectly formatted creation_date of VT '"
                                    + str(file)
                                    + '\' (length != 44). Please use EXACTLY the following format as in: "2017-11-29 13:56:41 +0000 (Wed, 29 Nov 2017)"',
                                )

                        except ValueError:
                            return (
                                -1,
                                "False or incorrectly formatted creation_date of VT '"
                                + str(file)
                                + "'",
                            )

                        return (0,)
        return -1, "No creation date has been found in VT '" + str(file) + "'."


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = is_creation_date_correct(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report("VTs with wrong or missing creation date", error)
        sys.exit(1)

    sys.exit(0)

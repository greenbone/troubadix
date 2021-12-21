#!/usr/bin/env python3

import re
import sys


def has_valid_script_add_preference_type(file):
    """This script checks the passed VT if it is using a script_add_preference not matching one of the following allowed strings
        passed to the 'type' function parameter:

        - checkbox
        - password
        - file
        - radio
        - entry

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

    # don't need to check VTs not having a script_add_preference() call
    if "script_add_preference" not in text:
        return (0,)

    preferences_matches = re.finditer(
        "\s*script_add_preference\s*\([^)]+type\s*:\s*['\"]([^'\"]+)['\"]\s*[^)]*\)\s*;",
        text,
    )
    if preferences_matches is None:
        return (0,)

    wrong_type_found = False
    wrong_type_report = (
        "VT '"
        + str(file)
        + "' is using an invalid or misspelled string passed to the type parameter of script_add_preference in the following line(s):\n"
    )
    valid_types = ["checkbox", "password", "file", "radio", "entry"]

    for preferences_match in preferences_matches:
        if (
            preferences_match is not None
            and preferences_match.group(1) is not None
        ):

            type = preferences_match.group(1)

            if type not in valid_types:

                # nb: This exists since years and it is currently unclear if we can change it so
                # we're excluding it here for now.
                if "ssh_authorization_init.nasl" in file and type == "sshlogin":
                    continue

                wrong_type_report = (
                    wrong_type_report + preferences_match.group(0) + "\n"
                )
                wrong_type_found = True

    if wrong_type_found:
        return -1, wrong_type_report

    return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if not files:
        sys.exit(0)

    for file in files:
        test = has_valid_script_add_preference_type(file)
        if test[0] == -1:
            error.append(file)

    if len(error) > 0:
        ci_helpers.report(
            "Files using an invalid or misspelled string passed to the type parameter of script_add_preference",
            error,
        )
        sys.exit(-1)

    sys.exit(0)

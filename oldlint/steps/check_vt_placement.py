#!/usr/bin/env python3

import re
import sys
import os


def run(file):
    """The script checks if the passed VT is using one of the two following families:

    - script_family("Service detection");
    - script_family("Product detection");

    and is correctly placed into the "root" of the VTs directory.

    Args:
        file: The VT that shall be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message
    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    text = open(file, encoding="latin-1").read()

    match = re.search(
        '^\s*script_family\s*\(\s*"(Product|Service) detection"\s*\)\s*;',
        text,
        re.MULTILINE,
    )
    if match is None:
        return (0,)

    match = re.search(
        "^\s*script_tag\s*\(\s*name\s*:\s*['\"]deprecated['\"]\s*,\s*value\s*:\s*TRUE\s*\)\s*;",
        text,
        re.MULTILINE,
    )
    if match is not None:
        return (0,)

    filename = os.path.basename(file)

    # nb: Path depends on the way the check is called (FULL/part run, CI run, ...)
    if (
        filename == file
        or os.path.join("./", filename) == file
        or os.path.join("scripts", filename) == file
        or os.path.join("./scripts", filename) == file
        or os.path.join("gsf", filename) == file
        or os.path.join("./gsf", filename) == file
        or os.path.join("scripts", "gsf", filename) == file
        or os.path.join("./scripts", "gsf", filename) == file
        or os.path.join("attic", filename) == file
        or os.path.join("./attic", filename) == file
        or os.path.join("scripts", "attic", filename) == file
        or os.path.join("./scripts", "attic", filename) == file
    ):
        return (0,)

    return (
        -1,
        "VT '" + str(file) + "' should be placed in the root directory." + "\n",
    )


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
            "VTs which should be placed in the root directory", error
        )
        sys.exit(1)

    sys.exit(0)

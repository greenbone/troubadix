#!/usr/bin/env python3

from pathlib import Path
from typing import List
import re

ENCODING = "latin-1"


def vt_placement(nasl_file: Path):
    """The script checks if the passed VT is using one of the
       two following families:

    - script_family("Service detection");
    - script_family("Product detection");

    and is correctly placed into the "root" of the VTs directory.

    Args:
        nasl_file: The VT that shall be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message
    """
    content = nasl_file.read_text(encoding=ENCODING)

    match = re.search(
        r'^\s*script_family\s*\(\s*"(Product|Service) detection"\s*\)\s*;',
        content,
        re.MULTILINE,
    )
    if match is None:
        return (0,)

    match = re.search(
        r'^\s*script_tag\s*\(\s*name\s*:\s*[\'"]deprecated[\'"]'
        r"\s*,\s*value\s*:\s*TRUE\s*\)\s*;",
        content,
        re.MULTILINE,
    )
    if match is not None:
        return (0,)

    # nb: Path depends on the way the check
    # is called (FULL/part run, CI run, ...)
    if (
        nasl_file.name == nasl_file
        or Path(f"./{nasl_file.name}") == nasl_file
        or Path(f"scripts/{nasl_file.name}") == nasl_file
        or Path(f"./scripts/{nasl_file.name}") == nasl_file
        or Path(f"gsf/{nasl_file.name}") == nasl_file
        or Path(f"./gsf/{nasl_file.name}") == nasl_file
        or Path(f"scripts/gsf/{nasl_file.name}") == nasl_file
        or Path(f"./scripts/gsf/{nasl_file.name}") == nasl_file
        or Path(f"attic/{nasl_file.name}") == nasl_file
        or Path(f"./attic/{nasl_file.name}") == nasl_file
        or Path(f"scripts/attic/{nasl_file.name}") == nasl_file
        or Path(f"./scripts/attic/{nasl_file.name}") == nasl_file
    ):
        return (0,)

    return (
        -1,
        f"VT '{str(nasl_file)}' should be placed in the root directory.\n",
    )


def check_nasl_files(nasl_files: List[Path]) -> None:
    for nasl_file in nasl_files:
        # Does only apply to NASL nasl_files.
        if nasl_file.suffix == ".nasl":
            vt_placement(nasl_file)


# if __name__ == "__main__":
#     import ci_helpers

#     error = []
#     nasl_files = ci_helpers.list_modified_files()
#     if nasl_files:
#         for nasl_file in nasl_files:
#             test = run(nasl_file)
#             if test[0] != 0:
#                 error.append(nasl_file)
#     else:
#         sys.exit(0)

#     if len(error) > 0:
#         ci_helpers.report(
#             "VTs which should be placed in the root directory", error
#         )
#         sys.exit(1)

#     sys.exit(0)

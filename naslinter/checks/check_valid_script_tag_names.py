#!/usr/bin/env python3

from pathlib import Path
from typing import List
import re

ENCODING = "latin-1"


def has_valid_script_tag_names(nasl_file):
    """This step checks if the name of the following script tag:

    - script_tag(name:"", value:"");

    is one of the following allowed ones:

    - script_tag(name:"solution", value:"");
    - script_tag(name:"qod_type", value:"");
    - script_tag(name:"cvss_base", value:"");
    - script_tag(name:"cvss_base_vector", value:"");
    - script_tag(name:"summary", value:"");
    - script_tag(name:"last_modification", value:"");
    - script_tag(name:"insight", value:"");
    - script_tag(name:"affected", value:"");
    - script_tag(name:"creation_date", value:"");
    - script_tag(name:"vuldetect", value:"");
    - script_tag(name:"impact", value:"");
    - script_tag(name:"deprecated", value:"");
    - script_tag(name:"qod", value:"");
    - script_tag(name:"severity_vector", value:"");
    - script_tag(name:"severity_origin", value:"");
    - script_tag(name:"severity_date", value:"");
    - script_tag(name:"solution_method", value:"");
    # nb: Not fully implemented in GVM yet (further implementation "on hold").

    Args:
        nasl_file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message
    """

    content = nasl_file.read_text(encoding=ENCODING)
    found_tags = ""

    allowed_script_tag_names = [
        "solution",
        "solution_type",
        "qod_type",
        "cvss_base",
        "cvss_base_vector",
        "summary",
        "last_modification",
        "insight",
        "affected",
        "creation_date",
        "vuldetect",
        "impact",
        "deprecated",
        "qod",
        "severity_vector",
        "severity_origin",
        "severity_date",
        "solution_method",
    ]

    matches = re.finditer(
        r'^ *script_tag *\( *name *: *["\']([^"\']+)["\'] *, *value *: *["\']',
        content,
        re.MULTILINE,
    )
    if matches is not None:
        for match in matches:
            if match.group(1) not in allowed_script_tag_names:
                found_tags += f"\n\t{match.group(0)}"

    if len(found_tags) > 0:
        return (
            -1,
            f"The VT '{str(nasl_file)}' is using one or more of "
            f"the following not allowed names:{str(found_tags)}",
        )

    return (0,)


def check_nasl_files(nasl_files: List[Path]) -> None:
    for nasl_file in nasl_files:
        # Does only apply to NASL nasl_files.
        if nasl_file.suffix == ".nasl":
            has_valid_script_tag_names(nasl_file)


# if __name__ == "__main__":
#     import ci_helpers

#     error = []
#     nasl_files = ci_helpers.list_modified_nasl_files()
#     if nasl_files:
#         for nasl_file in nasl_files:
#             test = has_valid_script_tag_names(nasl_file)
#             if test[0] != 0:
#                 error.append(nasl_file)
#     else:
#         sys.exit(0)

#     if len(error) > 0:
#         ci_helpers.report("VTs using not allowed script_tag names", error)
#         sys.exit(1)

#     sys.exit(0)

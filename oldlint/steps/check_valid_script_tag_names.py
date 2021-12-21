#!/usr/bin/env python3

import re
import sys


def has_valid_script_tag_names(file):
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
    - script_tag(name:"solution_method", value:""); # nb: Not fully implemented in GVM yet (further implementation "on hold").

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

    script_tag_match = re.finditer(
        "^ *script_tag *\( *name *: *[\"']([^\"']+)[\"'] *, *value *: *[\"']",
        text,
        re.MULTILINE,
    )
    if script_tag_match is not None:
        for match in script_tag_match:
            if match.group(1) not in allowed_script_tag_names:
                found_tags += "\n\t" + match.group(0)

    if len(found_tags) > 0:
        return -1, "The VT '" + str(
            file
        ) + "' is using one or more of the following not allowed names:" + str(
            found_tags
        )

    return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = has_valid_script_tag_names(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report("VTs using not allowed script_tag names", error)
        sys.exit(1)

    sys.exit(0)

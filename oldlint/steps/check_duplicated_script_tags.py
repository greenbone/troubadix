#!/usr/bin/env python3

import re
import sys


def has_duplicate_script_tags(file):
    """This script checks if one of the following script tags exists multiple times within the same VT:

    - script_mandatory_keys();
    - script_name();
    - script_require_keys();
    - script_exclude_keys();
    - script_oid();
    - script_require_ports();
    - script_require_udp_ports();
    - script_copyright();
    - script_family();
    - script_category();
    - script_cve_id();
    - script_version();
    - script_bugtraq_id();
    - script_dependencies();
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

    simple_calls_to_check = [
        "mandatory_keys",
        "name",
        "require_keys",
        "exclude_keys",
        "oid",
        "require_ports",
        "require_udp_ports",
        "copyright",
        "family",
        "category",
        "cve_id",
        "version",
        "bugtraq_id",
        "dependencies",
    ]
    script_tags_to_check = [
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
    ]

    for check in simple_calls_to_check:

        # TBD: script_name might also look like this: script_name("MyVT (Windows)");
        match = re.findall(
            "^ *script_" + check + " *\([^)]+\) *;", text, re.MULTILINE
        )
        if match and len(match) > 1:

            # This is allowed, see e.g. gb_netapp_data_ontap_consolidation.nasl
            if check == "dependencies" and "FEED_NAME" in text:
                continue

            found_tags += "\n\t" + match[0].partition("(")[0]

    for check in script_tags_to_check:
        match = re.findall(
            "^ *script_tag *\( *name *: *[\"']"
            + check
            + "[\"'] *, *value *: *.*?(?=\) *;)+\) *;",
            text,
            re.MULTILINE | re.DOTALL,
        )
        if match and len(match) > 1:
            found_tags += "\n\t" + match[0].partition(",")[0]

    if len(found_tags) > 0:
        return -1, "The VT '" + str(
            file
        ) + "' is using the following duplicated script tags:" + str(found_tags)

    return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = has_duplicate_script_tags(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report("VTs has duplicated script tags", error)
        sys.exit(1)

    sys.exit(0)

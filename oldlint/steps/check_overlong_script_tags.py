#!/usr/bin/env python3

import re
import sys

# Max amount of allowed chars for each tag
tag_limit = 3000


def contains_overlong_script_tags(file):
    """
    Checks a given file if any of the script_tag(name:"(summary|impact|affected|insight|vuldetect|solution)", value:"")
    contains an overlong line within the value string.

    Background for this is that e.g. auto generated LSCs where are created by parsing an advisory
    and the whole content is placed in such a tag which could be quite large.

    Args:
            file: The VT that is going to be checked

    Returns:
            tuples: 0 => Success, no message
                   -1 => Error, with error message
    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    # The summary of those contains a description of each parameter which can't be stripped down.
    if "gb_nmap6_" in file:
        return (0,)

    # This has so many vulnerabilities, and we wanna at least mention each of them, so no way to shorten it down.
    if "monstra_cms_mult_vuln" in file:
        return (0,)

    # These have auto-generated affected tags which we don't want to shorten down.
    if "gb_huawei-sa-" in file:
        return (0,)

    # Needs a description for each option which we don't want to shorten down.
    if "lsc_options.nasl" in file:
        return (0,)

    text = open(file, encoding="latin-1").read()
    tag_matches = re.finditer(
        '(script_tag\(name\s*:\s*"(summary|impact|affected|insight|vuldetect|solution)"\s*,\s*value\s*:\s*")([^"]+)"',
        text,
    )
    overlong_tags = ""
    if tag_matches is not None:
        for match in tag_matches:
            if match is not None and match.group(3) is not None:
                match_len = len(match.group(3))
                if match_len > tag_limit:
                    overlong_tags += (
                        "\n\tCurrent chars "
                        + str(match_len)
                        + " in: "
                        + match.group(0).partition(",")[0]
                    )

    if len(overlong_tags) > 0:
        return -1, "The following script_tags of VT '" + str(
            file
        ) + "' are longer then the current allowed limit '" + str(
            tag_limit
        ) + "':" + str(
            overlong_tags
        )

    return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = contains_overlong_script_tags(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report(
            "VTs with a tag containing more then " + str(tag_limit) + " chars",
            error,
        )
        sys.exit(1)

    sys.exit(0)

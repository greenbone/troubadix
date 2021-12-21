#!/usr/bin/env python3

import re
import sys


def contains_no_illegal_chars(file):
    """
    Currently the following chars are not allowed in every script_tag(name:"", value:"") :

    |
    = (Note: currently temporary disabled)

    Background for this is that the tags are saved in the internal VT cache like
    Tag1=Foo|Tag2=Bar|Tag3=Baz

    Additionally the ';' shouldn't be used in the "summary", "impact", "vuldetect",
    "insight" and "solution" script_tags because it will be replaced with a space in GSA

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

    final_report = ""
    illegal_character_tags = ""
    replaced_character_tags = ""

    tag_matches = re.finditer(
        '(script_tag\(name\s*:\s*"(summary|impact|affected|insight|vuldetect|solution)"\s*,\s*value\s*:\s*")([^"]+)"',
        text,
    )

    if tag_matches is not None:
        for tag_match in tag_matches:
            if tag_match is not None and tag_match.group(3) is not None:

                illegal_character_matches = re.finditer(
                    ".*([|]).*", tag_match.group(3)
                )
                if illegal_character_matches is not None:
                    for illegal_character_match in illegal_character_matches:
                        if (
                            illegal_character_match is not None
                            and illegal_character_match.group(1) is not None
                        ):
                            illegal_character_tags += (
                                "\n\t"
                                + tag_match.group(0).partition(",")[0]
                                + ", hit: "
                                + illegal_character_match.group(0)
                            )

                replaced_character_matches = re.finditer(
                    ".*([;]).*", tag_match.group(3)
                )
                if replaced_character_matches is not None:
                    for replaced_character_match in replaced_character_matches:
                        if (
                            replaced_character_match is not None
                            and replaced_character_match.group(1) is not None
                        ):
                            replaced_character_tags += (
                                "\n\t"
                                + tag_match.group(0).partition(",")[0]
                                + ", hit: "
                                + replaced_character_match.group(0)
                            )

    if len(illegal_character_tags) > 0:
        final_report += (
            "\nThe following script_tags of VT '"
            + str(file)
            + "' contain illegal characters('|'):"
            + str(illegal_character_tags)
            + "\n"
        )

    if len(replaced_character_tags) > 0:
        final_report += (
            "\nThe following script_tags of VT '"
            + str(file)
            + "' contain a ';' character, which will be replaced with a space in GSA:"
            + str(replaced_character_tags)
        )

    if len(final_report) > 0:
        return -1, final_report

    return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = contains_no_illegal_chars(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report("VTs with ';' or '|' in a script tag", error)
        sys.exit(1)

    sys.exit(0)

#!/usr/bin/env python3

import re
import sys


def has_wrong_newlines(file):
    """This script checks the passed VT for the existence of CRLF and CR newlines.
    An error will be thrown if the newlines are incorrectly formatted. Only UNIX newlines (LF) are valid.

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message

    """

    text = open(file, "rb")
    affected = ""

    for index, line in enumerate(text.readlines()):
        if line[-2:] == "\r\n" or line[-1:] == "\r":
            affected = 1
            break

    if affected:
        return (
            -1,
            "VT '"
            + str(file)
            + "' contains CR or CRLF newlines. Please convert it to Unix format (LF).",
        )

    return (0,)


def has_unallowed_newlines_in_script_tags(file):
    """This script checks the passed VT for the existence of newlines in the script_name() and script_copyright() tags.
    An error will be thrown if newlines have been found in the aforementioned tags.

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
    err = False
    name = ""
    copyright = ""

    name_tag_result = re.search(
        "script_name\s*\(\s*['\"]([^\n]+)['\"]\s*\)\s*;", text
    )
    # TODO: A few remaining have script_name( "myname"), use the following instead of
    # the above once those where migrated to script_name("myname") and remote the
    # "not in" handling below as well.
    # name_tag_result = re.search('script_name\s*\([\'"]([^\n]+)[\'"]\s*\)\s*;', text)

    copyright_tag_result = re.search(
        "script_copyright\s*\(['\"]([^\n]+)['\"]\s*\)\s*;", text
    )

    if name_tag_result is None and "script_name(name);" not in text:
        err = True
        name = "- script_name()"
    if copyright_tag_result is None:
        err = True
        copyright = "- script_copyright()"

    if err:
        return (
            -1,
            "VT '"
            + str(file)
            + "' contains a script_tag with an unallowed newline.\nPlease remove the newline out of the following tag(s): "
            + name
            + " "
            + copyright
            + ".",
        )
    return (0,)


if __name__ == "__main__":
    import ci_helpers

    wrong_newlines = []
    newline_in_tags = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test1 = has_wrong_newlines(file)
            test2 = has_unallowed_newlines_in_script_tags(file)
            if test1[0] != 0:
                wrong_newlines.append(file)
            if test2[0] != 0:
                newline_in_tags.append(file)
    else:
        sys.exit(0)

    if len(wrong_newlines) > 0:
        ci_helpers.report(
            "VTs with wrong encoded newlines (CRLF or CR)", wrong_newlines
        )

    if len(newline_in_tags) > 0:
        ci_helpers.report(
            "VTs with a newline in script_name or script_copyright tag",
            newline_in_tags,
        )

    if len(wrong_newlines) > 0 or len(newline_in_tags) > 0:
        sys.exit(1)

    sys.exit(0)

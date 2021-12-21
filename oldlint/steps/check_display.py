#!/usr/bin/env python3

import re
import sys


def is_using_display_if_commented(file):
    """This script checks the passed VT for the use of the display() function being protected by a comment or
    an if statement with the help of regular expression.

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
                1 => Success, with debug messages
    """

    text = open(file, encoding="latin-1").read()

    if "display" not in text:
        return (0,)

    display_matches = re.finditer(
        ".*(if\s*\(|#).*(display\s*\([^)]+\)\s*;)", text
    )
    if display_matches is None:
        return (0,)

    found_matches = ""

    for display_match in display_matches:
        if display_match is not None and display_match.group(0):
            found_matches += "\n\n" + display_match.group(0)

    if len(found_matches) > 0:
        return (
            1,
            "VT/Include '"
            + str(file)
            + "' is using a display() function which is protected by a comment or an if statement at:\n"
            + found_matches,
        )
    return (0,)


def is_using_display(file):
    """This script checks the passed VT for the use of the display() variable with the help of regular expression.
    An error will be thrown if the VT contains a display function which is not being protected by a comment or an if statement.

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message
    """

    text = open(file, encoding="latin-1").read()

    if "display" not in text:
        return (0,)

    display_matches = re.finditer(".*(display\s*\([^)]+\)\s*;)", text)
    if display_matches is None:
        return (0,)

    found_matches = ""

    for display_match in display_matches:
        if display_match is not None and display_match.group(0):
            dis_match = display_match.group(0)

            # Known false positives because the if_match check above can't detect something like e.g.:
            # if( debug )
            #   display("foo");
            if "ssh_func.inc" in file and "display( debug_str )" in dis_match:
                continue

            if (
                "gb_treck_ip_stack_detect.nasl" in file
                and 'display("---[' in dis_match
            ):
                continue

            if "ike_isakmp_func.inc" in file and 'display( "---[' in dis_match:
                continue

            if "pcap_func.inc" in file and 'display( "---[' in dis_match:
                continue

            if (
                "os_eol.inc" in file
                and 'display( "DEBUG: Base CPE' in dis_match
            ):
                continue

            if (
                "gsf/dicom.inc" in file
                or "global_settings.inc" in file
                or "rdp.inc" in file
                or "bin.inc" in file
            ):
                continue

            if "DDI_Directory_Scanner.nasl" in file and ":: Got a" in dis_match:
                continue

            if_comment_match = re.search(
                "(if[\s]*\(|#).*display\s*\(", dis_match
            )
            if (
                if_comment_match is not None
                and if_comment_match.group(0) is not None
            ):
                continue

            found_matches += "\n\n" + dis_match

    if len(found_matches) > 0:
        return (
            -1,
            "VT/Include '"
            + str(file)
            + "' is using a display() function at:\n"
            + found_matches,
        )
    return (0,)


if __name__ == "__main__":
    import ci_helpers

    error, debug = [], []
    files = ci_helpers.list_modified_files()
    if not files:
        sys.exit(0)

    for file in files:
        test = is_using_display(file)
        if test[0] == -1:
            error.append(file)

        test = is_using_display_if_commented(file)
        if test[0] == 1:
            debug.append(file)

    if len(debug) > 0:
        ci_helpers.report(
            "Files using a display() function protected by a comment or an if statement",
            debug,
        )

    if len(error) > 0:
        ci_helpers.report("Files using a display() function", error)
        sys.exit(-1)

    sys.exit(0)

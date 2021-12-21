#!/usr/bin/env python3

import re, os, sys


def has_wrong_set_get_kb_call(file):

    """
    Checks a given file if it calls any of the following functions setting or getting KB entries
    in a wrong way like e.g. with too much or too less function parameters.

    - set_kb_item(name:"kb/key", value:"value");
    - replace_kb_item(name:"kb/key", value:"value");
    - get_kb_item("kb/key");
    - get_kb_list("kb/key");

    Wrong examples which needs to be reported:

    - set_kb_item("kb/key", value:"value");
    - replace_kb_item(name:"kb/key", "value");
    - replace_kb_item(name:"kb/key");
    - replace_kb_item(name:"kb/key", name:"kb/key");
    - get_kb_item(name:"kb/key");

    Args:
            file: The VT/Include that is going to be checked

    Returns:
            tuples: 0 => Success, no message
                   -1 => Error, with error message
    """

    text = open(file, encoding="latin-1").read()
    found_wrong_set_calls = ""
    found_wrong_get_calls = ""
    final_report = ""
    param_re = re.compile("(name|value) ?:")

    set_matches = re.finditer(
        "(set|replace)_kb_item\s*\(([^)]+)\)\s*;", text, re.MULTILINE
    )
    if set_matches is not None:
        for set_match in set_matches:
            if set_match is not None and set_match.group(2) is not None:
                set_param_match = re.findall(param_re, set_match.group(2))
                if not set_param_match or len(set_param_match) != 2:
                    found_wrong_set_calls += "\n\t" + set_match.group(0)

    get_matches = re.finditer(
        "get_kb_(item|list)\s*\(([^)]+)\)\s*;", text, re.MULTILINE
    )
    if get_matches is not None:
        for get_match in get_matches:
            if get_match is not None and get_match.group(2) is not None:
                get_param_match = re.findall(param_re, get_match.group(2))
                if get_param_match and len(get_param_match) > 0:
                    found_wrong_get_calls += "\n\t" + get_match.group(0)

    if len(found_wrong_set_calls) > 0:
        final_report += (
            "The following functions of VT/Include '"
            + str(file)
            + "' are missing a 'name:' and/or 'value:' parameter:"
            + str(found_wrong_set_calls)
        )

    if len(found_wrong_get_calls) > 0:
        if len(found_wrong_set_calls) > 0:
            final_report += "\n\n"
        final_report += (
            "The following functions of VT/Include '"
            + str(file)
            + "' are using a non-existent 'name:' and/or 'value:' parameter:"
            + str(found_wrong_get_calls)
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
            test = has_wrong_set_get_kb_call(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report(
            "VTs using functions set_kb_item(), replace_kb_item(), get_kb_item() or get_kb_list() wrong",
            error,
        )
        sys.exit(1)

    sys.exit(0)

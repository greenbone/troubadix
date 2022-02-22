#!/usr/bin/env python3

import re
import sys


def is_using_only_current_functions(file):
    """
    Following functions / description items are outdated:
    script_summary()
    script_id()
    security_note()
    security_warning()
    security_hole()
    script_description()
    script_tag("risk_factor", SEVERITY);

    This script checks if any of those are used

    Args:
        file: Name of the VT to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message

    """

    text = open(file, encoding="latin-1").read()

    deprecated_functions = {
        'script_summary(), use script_tag(name:"summary", value:"") instead': "script_summary\s*\([^)]*\)",
        "script_id(), use script_oid() with the full OID instead": "script_id\s*\([0-9]+\)",
        "security_note()": "security_note\s*\([^)]*\)",
        "security_warning()": "security_warning\s*\([^)]*\)",
        "security_hole()": "security_hole\s*\([^)]*\)",
        "script_description()": "script_description\s*\([^)]*\)",
        'script_tag(name:"risk_factor", value: SEVERITY)': 'script_tag\s*\(\s*name:\s*"risk_factor"[^)]*\)',
    }

    functions_used = ""

    for key in deprecated_functions:
        if re.search(deprecated_functions[key], text):
            functions_used += "\n\t" + key

    if len(functions_used) > 0:
        return -1, "The following functions of VT '" + str(
            file
        ) + "' are deprecated:" + str(functions_used)

    else:
        return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = is_using_only_current_functions(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report("VTs using deprecated functions", error)
        sys.exit(1)

    sys.exit(0)

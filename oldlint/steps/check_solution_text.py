#!/usr/bin/env python3

import re
import sys


def is_using_correct_solution_text(file):
    """
    There are specific guidelines on the syntax for the solution tag on VTs
    with the solution_type "NoneAvailable" or "WillNotFix" available at:

    https://community.greenbone.net/t/vt-development/226 (How to handle VTs with "no solution" for the user)

    This script checks if those guidelines are upheld.

    Args:
        file: Name of the VT to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message
    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    text = open(file, encoding="latin-1").read()

    # Two different strings, one for RegEx one for output
    correct_none_available_pattern = 'script_tag\s*\(\s*name\s*:\s*"solution"\s*,\s*value\s*:\s*"No\s+known\s+solution\s+is\s+available\s+as\s+of\s+(0[1-9]|[12][0-9]|3[01])(st|nd|rd|th)\s+(January|February|March|April|May|June|July|August|September|October|November|December),\s+20[0-9]{2}\.\s+Information\s+regarding\s+this\s+issue\s+will\s+be\s+updated\s+once\s+solution\s+details\s+are\s+available\.'
    correct_none_available_syntax = '  script_tag(name:"solution", value:"No known solution is available as of dd(st|nd|rd|th) mmmmmmmm, yyyy.\n  Information regarding this issue will be updated once solution details are available.");'

    # same here
    correct_will_not_fix_pattern = 'script_tag\s*\(\s*name\s*:\s*"solution"\s*,\s*value\s*:\s*"(No\s+solution\s+(was\s+made\s+available\s+by\s+the\s+vendor|is\s+required)\.\s+Note:.+|(No\s+solution\s+was\s+made\s+available\s+by\s+the\s+vendor|No\s+known\s+solution\s+was\s+made\s+available\s+for\s+at\s+least\s+one\s+year\s+since\s+the\s+disclosure\s+of\s+this\s+vulnerability\.\s+Likely\s+none\s+will\s+be\s+provided\s+anymore)\.\s+General\s+solution\s+options\s+are\s+to\s+upgrade\s+to\s+a\s+newer\s+release,\s+disable\s+respective\s+features,\s+remove\s+the\s+product\s+or\s+replace\s+the\s+product\s+by\s+another\s+one\.)'
    correct_will_not_fix_syntax = '  script_tag(name:"solution", value:"No known solution was made available for at least one year\n  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution\n  options are to upgrade to a newer release, disable respective features, remove the product or\n  replace the product by another one.");'
    correct_will_not_fix_syntax += "\n\n"
    correct_will_not_fix_syntax += '  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution\n  options are to upgrade to a newer release, disable respective features, remove the product or\n  replace the product by another one.");'
    correct_will_not_fix_syntax += "\n\n"
    correct_will_not_fix_syntax += '  script_tag(name:"solution", value:"No solution was made available by the vendor.\n\n  Note: <add a specific note for the reason here>.");'
    correct_will_not_fix_syntax += "\n\n"
    correct_will_not_fix_syntax += '  script_tag(name:"solution", value:"No solution is required.\n\n  Note: <add a specific note for the reason here, e.g. CVE was disputed>.");'

    if (
        re.search(
            'script_tag\s*\(\s*name\s*:\s*"solution_type"\s*,\s*value\s*:\s*"NoneAvailable"\s*\);',
            text,
        )
        and not re.search(correct_none_available_pattern, text)
    ):
        return (
            -1,
            "The VT '"
            + str(file)
            + "' with solution type 'NoneAvailable' is using an incorrect syntax in the solution text. Please use (EXACTLY):\n\n"
            + correct_none_available_syntax,
        )
    elif (
        re.search(
            'script_tag\s*\(\s*name\s*:\s*"solution_type"\s*,\s*value\s*:\s*"WillNotFix"\s*\);',
            text,
        )
        and not re.search(correct_will_not_fix_pattern, text)
    ):
        return (
            -1,
            "The VT '"
            + str(file)
            + "' with solution type 'WillNotFix' is using an incorrect syntax in the solution text. Please use one of these (EXACTLY):\n\n"
            + correct_will_not_fix_syntax,
        )
    else:
        return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = is_using_correct_solution_text(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report(
            "VTs with solution_type 'NoneAvailable' or 'WillNotFix' using wrong solution text",
            error,
        )
        sys.exit(1)

    sys.exit(0)

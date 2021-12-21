#!/usr/bin/env python3

import re
import sys
import subprocess


def subprocess_cmd(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    proc_stdout = process.communicate()[0].strip()
    return proc_stdout


def run(file):
    """The script checks (via git diff) if the passed VT has changed both of the following two tags
    via the replace_svn_props.py script:

    - script_version();
    - script_tag(name:"last_modification", value:"");

    An error will be thrown if one or both tags where unchanged.

    Args:
        file: The VT that shall be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message
    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    text = subprocess_cmd(
        "git -c color.status=false --no-pager diff --cached " + file
    ).decode("latin-1")
    report = ""

    # if changed the following two examples needs to be in the git output:
    #
    # +  script_version("2019-03-21T12:19:01+0000");")
    #
    # +  script_tag(name:"last_modification", value:"2019-03-21 12:19:01 +0000 (Thu, 21 Mar 2019)");
    match_ver_modified = re.search(
        '^\+\s*script_version\("[0-9\-\:\+T]{24}"\);', text, re.MULTILINE
    )
    if match_ver_modified is None:
        report += (
            "Changed VT '"
            + str(file)
            + "' has a not updated script_version();."
            + "\n"
        )

    match_last_modified = re.search(
        '^\+\s*script_tag\(name:"last_modification",\svalue:"[A-Za-z0-9\:\-\+\,\s\(\)]{44}"\);',
        text,
        re.MULTILINE,
    )
    if match_last_modified is None:
        report += (
            "Changed VT '"
            + str(file)
            + '\' has a not updated script_tag(name:"last_modification".'
            + "\n"
        )

    if len(report) > 0:
        report += "\nPlease run ./replace_svn_props.py to update both tags."
        return -1, report

    return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = run(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report(
            "VTs with unchanged script_version or last_modification tag(s)",
            error,
        )
        sys.exit(1)

    sys.exit(0)

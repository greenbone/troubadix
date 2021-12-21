#!/usr/bin/env python3

import subprocess, sys, os, re


def subprocess_cmd(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    proc_stdout = process.communicate()[0].decode("latin-1").strip()
    return proc_stdout


def is_oid_unique(file):
    """This script reads the OID from the file and runs grep to find out if
    the OID is used in more than one file.

    Args:
        file: The VT that is going to be checked
    Returns:
        tuples: 0 => Success, no message
                1 => Success, with debug message
               -1 => Error, with error message
    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    text = open(file, encoding="latin-1").read()
    oid = re.search('script_oid\("([0-9.]+)"\);', text)

    if oid is not None and oid.group(1) is not None:
        files = subprocess_cmd(
            "grep -R 'script_oid(\"" + oid.group(1) + "\");' . --include=*.nasl"
        ).splitlines()
        file_count = len(files)
        if file_count == 1:
            return (0,)
        else:
            output_text = (
                "OID '"
                + oid.group(1)
                + "' of VT '"
                + str(file)
                + "' already in use in following files:"
            )
            for i in range(0, file_count):
                if re.search(file, files[i]) is None:
                    output_text += "\r\n- '" + str(files[i])
            return -1, output_text
    else:
        return 1, "No OID found in VT '" + str(file) + "'"


if __name__ == "__main__":
    import ci_helpers

    debug = []
    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = is_oid_unique(file)
            if test[0] == -1:
                error.append(file)
            if test[0] == 1:
                debug.append(file)
    else:
        sys.exit(0)

    if len(debug) > 0:
        ci_helpers.report("Could not find OID in VTs", debug)

    if len(error) > 0:
        ci_helpers.report("VTs using already existing OIDs", error)
        sys.exit(1)

    sys.exit(0)

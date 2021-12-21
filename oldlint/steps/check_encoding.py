#!/usr/bin/env python3

import subprocess, re, os
import sys

missing_magic_module = False

# IMPORTANT!
# This is the magic module installed via "pip install python-magic"
# There is a module of the same name in the APT repository, but running this script using that package won't work
try:
    import magic
except:
    missing_magic_module = True


def subprocess_cmd(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    proc_stdout = process.communicate()[0].strip()
    return proc_stdout


def check_and_report_lines(file):
    """This function reports the lines of a script containing the wrong encoding with the help of python-magic.
    Concerning the python package, an error will be thrown if no magic module has been found or a wrong one is being used.
    The step itself will throw an error if the VT contains non-ASCII characters.

    Args:
        file: The VT that is going to be checked
    """

    report = ""

    with open(file, "rt", encoding="latin-1") as f:
        for line in f:
            # Only the ASCII and extended ASCII for now...
            # https://www.ascii-code.com/
            # encoding = re.search('[^\x00-\xFF]', line)
            # Temporary only check for chars in between 7f-9f like in the old Feed-QA...
            encoding = re.search("[\x7F-\x9F]", line)
            if encoding is not None:
                report += "\n" + line

    return report


def is_latin_1(file):
    """This script checks the VT's encoding

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message

    """

    if missing_magic_module:
        return (
            -1,
            "magic module required. Please install via 'pip install python-magic'.",
        )

    try:
        m = magic.Magic(mime_encoding=True)
    except TypeError:
        return (
            -1,
            "Wrong magic module (e.g. python-magic from Debian) installed. "
            "Please uninstall this package and install the required module via "
            "'pip install python-magic' / 'pip3 install python-magic'.",
        )

    text = open(file, encoding="latin-1").read()
    encoding = m.from_buffer(text)
    right_encoding = encoding == "latin-1" or encoding == "us-ascii"
    if right_encoding:
        return (0,)

    # Check, if text contains non-ascii characters either way
    report = check_and_report_lines(file)
    if len(report) > 0:
        report = (
            "VT '" + str(file) + "' contains non-ASCII characters "
            "at the following lines:\n" + report
        )
        return -1, report
    return (0,)


# nb: The above code currently has some issues to detect the encoding so
# it is currently temporary replaced by this function.
def check_encoding(file):

    # Looking for VTs with wrong encoding...
    encoding = subprocess_cmd(
        "LC_ALL=C file " + str(file) + " | grep 'UTF-8'"
    ).decode("latin-1")
    if len(encoding) > 0:
        return -1, "VT '" + str(file) + "' has a wrong encoding."

    # Looking for VTs with characters coded with codepoints between 7f-9f
    report = check_and_report_lines(file)
    if len(report) > 0:
        report = (
            "VT '" + str(file) + "' has incorrect characters between 7f-9f "
            "at the following lines:\n" + report
        )
        return 1, report
    return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = check_encoding(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report(
            "VTs having incorrect characters between 7f-9f", error
        )
        sys.exit(1)

    sys.exit(0)

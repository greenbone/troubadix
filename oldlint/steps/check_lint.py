#!/usr/bin/env python3

import subprocess
import os
import sys


def subprocess_lint(command):
    """This script creates a subprocess and obtains its output

    Args:
        command: The command that is being executed inside the subprocess

    Returns:
        string: The outcome of the executed command for further processing

    """

    process = subprocess.Popen(
        str(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
    )
    out, err = process.communicate()

    report = ""
    if err:
        report += err.decode("latin-1")
    if out:
        report += out.decode("latin-1")
    return report


def is_lint_correct(file, vtdir, dir_list, inc_list, full):
    """'openvas-nasl-lint' is required for this step to be executable!
    This script opens a shell in a subprocess and executes 'openvas-nasl-lint' to check the VT/Include for errors.
    If any kind of error is being found during the subprocess, an error will be thrown showing its source.

    Args:
        file: The VT/Include that is going to be checked
        vtdir: The directory of the VT scripts
        dir_list: The list of dirs to check if a full run of the whole VT dir was requested
        inc_list: The list of .inc files to check if a full run of the whole VT dir and a recursive check was requested
        full: If a full run on the whole VT dir was requested

    Returns:
        tuples: 0 => Success, no message
                1 => Success, with debug messages
               -1 => Error, with error message

    """

    found_error = False
    found_debug = False
    error_report = ""
    debug_report = ""
    check_exts = ["*.inc", "*.nasl"]

    if full:
        if isinstance(dir_list, list):
            for dir in dir_list:

                # Doesn't have any .inc and .nasl files so no need to check...
                if "report_formats" in dir:
                    continue

                for ext in check_exts:
                    if dir == "./":
                        check = ext
                    else:
                        check = "/" + ext
                    lint = subprocess_lint(
                        "openvas-nasl-lint -i "
                        + str(vtdir)
                        + " "
                        + str(dir)
                        + check
                    )

                    # For directories which doesn't include one of the checked file extensions,
                    # e.g. "./gsf/2008/*.nasl: Not able to open nor to locate it in include paths"
                    if (
                        ext
                        + ": Not able to open nor to locate it in include paths"
                        in lint
                    ):
                        continue

                    if " errors found" not in lint:
                        debug_report += "\n" + str(lint)
                        found_debug = True
                    # nb: "Cannot compile regex" was added here because openvas-nasl-lint currently
                    # doesn't treat these as errors. See SC-175.
                    elif (
                        "0 errors found" not in lint
                        or "Cannot compile regex" in lint
                    ):
                        error_report += "\n" + str(lint)
                        found_error = True

    else:
        lint = subprocess_lint(
            "openvas-nasl-lint -i " + str(vtdir) + " " + str(file)
        )
        if " errors found" not in lint:
            debug_report += "\n" + str(lint)
            found_debug = True
        # nb: "Cannot compile regex" was added here because openvas-nasl-lint currently
        # doesn't treat these as errors. See SC-175.
        elif "0 errors found" not in lint or "Cannot compile regex" in lint:
            error_report += "\n" + str(lint)
            found_error = True

    if found_error:
        return -1, error_report
    elif found_debug:
        return 1, debug_report
    else:
        return (0,)


if __name__ == "__main__":
    import ci_helpers

    error, debug = [], []
    files = ci_helpers.list_modified_files()
    if not files:
        sys.exit(0)

    os.chdir("scripts/")
    scripts_dir = os.getcwd()

    for file in files:
        corrected_file_path = ci_helpers.filepath_without_scripts_dir(file)
        test = is_lint_correct(
            file=corrected_file_path,
            vtdir=scripts_dir,
            dir_list=False,
            inc_list=False,
            full=False,
        )
        if test[0] == -1:
            error.append(file)
        if test[0] == 1:
            debug.append(file)

    if len(debug) > 0:
        ci_helpers.report("OpenVAS NASL Lint run failed", debug)

    if len(error) > 0:
        ci_helpers.report("VTs/Includes with OpenVAS NASL Lint errors", error)
        sys.exit(-1)

    sys.exit(0)

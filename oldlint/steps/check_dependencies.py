#!/usr/bin/env python3

import re, os.path
import sys


def is_dependency_existing(file):
    """This script checks whether the files used in script_dependencies() exist on the local filesystem.
    An error will be thrown if a dependency could not be found.

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
                1 => Success, with debug messages
               -1 => Error, with error message

    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    text = open(file, encoding="latin-1").read()
    dependencies_matches = re.finditer(
        "script_dependencies\s*\(([^)]+)\);", text, re.MULTILINE
    )

    if dependencies_matches is not None:

        missing = ""
        illegal = ""
        problematic = ""

        for dependencies_match in dependencies_matches:
            if (
                dependencies_match is not None
                and dependencies_match.group(1) is not None
            ):

                dependencies = dependencies_match.group(1)

                # Remove single and/or double quotes, spaces
                # and create a list by using the comma as a separator
                # TODO: find a better way for this as it would miss something like the following broken dependencies:
                # script_dependencies("redax  script_detect.nasl");
                # script_dependencies("redax'script_detect.nasl");
                dep_list = dependencies.replace("'", "")
                dep_list = dep_list.replace('"', "")
                dep_list = dep_list.replace(" ", "")
                dep_list = dep_list.replace("\n", "")
                dep_list = dep_list.split(",")

                for dep in dep_list:

                    # TODO: gsf/PCIDSS/PCI-DSS.nasl, gsf/PCIDSS/v2.0/PCI-DSS-2.0.nasl and GSHB/EL15/GSHB.nasl
                    # are using a variable which we currently can't handle.
                    if "+d+.nasl" in dep:
                        continue

                    # Debug as those might be correctly placed
                    if (
                        dep[:4] == "gsf/"
                        and dep[:11] != "gsf/PCIDSS/"
                        and dep[:11] != "gsf/Policy/"
                    ):
                        problematic += "\n\t" + dep
                    # Subdirectories only allowed for directories on a whitelist
                    elif (
                        "/" in dep
                        and dep[:5] != "GSHB/"
                        and dep[:7] != "Policy/"
                        and dep[:11] != "gsf/PCIDSS/"
                        and dep[:11] != "gsf/Policy/"
                        and dep[:4] != "gcf/"
                        and dep[:9] != "nmap_nse/"
                    ):
                        illegal += "\n\t" + dep

                    if not os.path.exists(
                        os.path.join("scripts", dep)
                    ) and not os.path.exists(dep):
                        missing += "\n\t" + dep

        if missing:
            return -1, "The following script_dependencies of VT '" + str(
                file
            ) + "' could not be found on the local filesystem:" + str(missing)
        if illegal:
            return -1, "The following script_dependencies of VT '" + str(
                file
            ) + "' contain subdirectories, which is not allowed:" + str(illegal)
        if problematic:
            return 1, "The following script_dependencies of VT '" + str(
                file
            ) + "' contain subdirectories, which might be misplaced:" + str(
                problematic
            )
    return (0,)


if __name__ == "__main__":
    import ci_helpers

    debug = []
    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = is_dependency_existing(file)
            if test[0] == -1:
                error.append(file)
            if test[0] == 1:
                debug.append(file)

    else:
        sys.exit(0)

    if len(debug) > 0:
        ci_helpers.report(
            "VTs with dependencies containing subdirectories, which might be misplaced",
            debug,
        )

    if len(error) > 0:
        ci_helpers.report("VTs with malformed or missing dependencies", error)
        sys.exit(1)

    sys.exit(0)

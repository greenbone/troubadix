#!/usr/bin/env python3

import re, os.path
import sys


def has_deprecated_dependency(file):
    """No VT should depend on other VTs that are marked as deprecated via:

        script_tag(name:"deprecated", value:TRUE);
        exit(66);

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
        "^\s*script_dependencies\s*\(([^)]{3,})\)\s*;", text, re.MULTILINE
    )
    if dependencies_matches is None:
        return (0,)

    deprecated_re = re.compile(
        "^\s*(exit\s*\(\s*66\s*\)\s*;|script_tag\s*\(\s*name\s*:\s*[\"']deprecated[\"']\s*,\s*value\s*:\s*TRUE\s*\)\s*;)",
        re.MULTILINE,
    )
    self_deprecated = re.search(deprecated_re, text)
    if self_deprecated is not None and self_deprecated.group(1) is not None:
        return (0,)

    error = ""
    debug = ""

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

                if not os.path.exists(
                    os.path.join("scripts", dep)
                ) and not os.path.exists(dep):
                    debug += (
                        "\n\t"
                        + str(dep)
                        + " (dependency of "
                        + str(file)
                        + " missing on the filesystem)"
                    )
                    continue

                dep_text = ""

                if os.path.exists(os.path.join("scripts", dep)):
                    dep_text = open(
                        os.path.join("scripts", dep), encoding="latin-1"
                    ).read()
                elif os.path.exists(dep):
                    dep_text = open(dep, encoding="latin-1").read()
                else:
                    continue

                dep_deprecated_matches = re.finditer(deprecated_re, dep_text)
                if dep_deprecated_matches is not None:
                    tmp_error = ""
                    for dep_deprecated_match in dep_deprecated_matches:
                        if (
                            dep_deprecated_match is not None
                            and dep_deprecated_match.group(1) is not None
                        ):
                            tmp_error += "\n\t" + str(
                                dep_deprecated_match.group(0)
                            )

                    if tmp_error:
                        error += (
                            "\n\t"
                            + str(file)
                            + " depends on "
                            + str(dep)
                            + " which is marked as deprecated in the following line(s):"
                            + tmp_error
                        )

    if error:
        return -1, str(error)

    if debug:
        return (
            1,
            "No check for deprecated dependencies possible due to VTs using a dependency which doesn't exist on the local filesystem:"
            + str(debug),
        )

    return (0,)


if __name__ == "__main__":
    import ci_helpers

    debug = []
    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = has_deprecated_dependency(file)
            if test[0] == -1:
                error.append(file)
            if test[0] == 1:
                debug.append(file)

    else:
        sys.exit(0)

    if len(debug) > 0:
        ci_helpers.report(
            "No check for deprecated dependencies possible due to VTs using a dependency which doesn't exist on the local filesystem",
            debug,
        )

    if len(error) > 0:
        ci_helpers.report("VTs having a dependency to a deprecated VT", error)
        sys.exit(1)

    sys.exit(0)

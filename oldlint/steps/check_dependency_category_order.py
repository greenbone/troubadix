#!/usr/bin/env python3

import re, os.path
import sys


def run(file):
    """No VT N should depend on scripts that are in a category that normally would be executed after the category of VT M.
        e.g. a VT N within the ACT_GATHER_INFO category (3) is not allowed to depend on a VT M within the ACT_ATTACK category (4).
        See https://github.com/greenbone/openvas-scanner/blob/master/misc/nvt_categories.h for a list of such category numbers.

        In addition it is not allowed for VTs to have a direct dependency to VTs from within the ACT_SCANNER category.

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

    own_category_match = re.search(
        "^\s*script_category\s*\(([^)]{3,})\)\s*;", text, re.MULTILINE
    )
    if own_category_match is None or own_category_match.group(1) is None:
        return 1, "VT '" + str(file) + "' is missing a script_category!"

    # See https://github.com/greenbone/openvas-scanner/blob/master/misc/nvt_categories.h for a list of the category numbers.
    id_category_dict = {
        "ACT_INIT": 0,
        "ACT_SCANNER": 1,
        "ACT_SETTINGS": 2,
        "ACT_GATHER_INFO": 3,
        "ACT_ATTACK": 4,
        "ACT_MIXED_ATTACK": 5,
        "ACT_DESTRUCTIVE_ATTACK": 6,
        "ACT_DENIAL": 7,
        "ACT_KILL_HOST": 8,
        "ACT_FLOOD": 9,
        "ACT_END": 10,
    }

    own_category = own_category_match.group(1)
    if own_category not in id_category_dict:
        return (
            1,
            "VT '"
            + str(file)
            + "' is using an unsupported category '"
            + str(own_category)
            + "'!",
        )

    own_category_int = id_category_dict.get(own_category)

    dependencies_matches = re.finditer(
        "^\s*script_dependencies\s*\(([^)]{3,})\)\s*;", text, re.MULTILINE
    )
    if dependencies_matches is None:
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
                dep_category_match = ""
                dep_category = ""

                if os.path.exists(os.path.join("scripts", dep)):
                    dep_text = open(
                        os.path.join("scripts", dep), encoding="latin-1"
                    ).read()
                elif os.path.exists(dep):
                    dep_text = open(dep, encoding="latin-1").read()
                else:
                    continue

                dep_category_match = re.search(
                    "^\s*script_category\s*\(([^)]{3,})\)\s*;",
                    dep_text,
                    re.MULTILINE,
                )
                if (
                    dep_category_match is None
                    or dep_category_match.group(1) is None
                ):
                    debug += (
                        "\n\t"
                        + str(dep)
                        + " (dependency of "
                        + str(file)
                        + " is missing a category)"
                    )
                    continue

                dep_category = dep_category_match.group(1)
                if dep_category not in id_category_dict:
                    debug += (
                        "\n\t"
                        + str(dep)
                        + " (dependency of "
                        + str(file)
                        + ") is using an unsupported category '"
                        + str(dep_category)
                        + "'!"
                    )
                    continue

                dep_category_int = id_category_dict.get(dep_category)

                if own_category_int < dep_category_int:
                    error += (
                        "\n\t"
                        + str(file)
                        + " with category number "
                        + str(own_category_int)
                        + " ("
                        + str(own_category)
                        + ") depends on "
                        + str(dep)
                        + " with category number "
                        + str(dep_category_int)
                        + " ("
                        + str(dep_category)
                        + "), but category number "
                        + str(own_category_int)
                        + " ("
                        + str(own_category)
                        + ") < category number "
                        + str(dep_category_int)
                        + " ("
                        + str(dep_category)
                        + ")"
                    )

                # nb: Currently not sure about the host_alive_detection.nasl dependency so excluding them for now.
                if (
                    dep_category == "ACT_SCANNER"
                    and str(dep) != "host_alive_detection.nasl"
                ):
                    error += (
                        "\n\t"
                        + str(file)
                        + " depends on "
                        + str(dep)
                        + " with category number "
                        + str(dep_category_int)
                        + " ("
                        + str(dep_category)
                        + ") but no VT is allowed to have a direct dependency to VTs in this category."
                    )

    if error:
        return -1, str(error)

    if debug:
        return (
            1,
            "No check for out-of-order dependencies possible due to VTs missing a script_category call, using an unsupported category or using a dependency that doesn't exist on the local filesystem:"
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
            test = run(file)
            if test[0] == -1:
                error.append(file)
            if test[0] == 1:
                debug.append(file)

    else:
        sys.exit(0)

    if len(debug) > 0:
        ci_helpers.report(
            "No check for out-of-order dependencies possible due to VTs missing a script_category call, using an unsupported category or using a dependency that doesn't exist on the local filesystem",
            debug,
        )

    if len(error) > 0:
        ci_helpers.report(
            "VTs with out-of-order / not allowed ordependencies", error
        )
        sys.exit(1)

    sys.exit(0)

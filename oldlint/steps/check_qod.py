#!/usr/bin/env python3

import re
import sys


def is_qod_correct(file):
    """The script checks the passed VT for the existence / validity of its QoD with the help of regular expression.
    An error will be thrown if the VT contains multiple QoD expressions or if an invalid QoD type/value is being used.

    Args:
        file: The VT that shall be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message
    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    text = open(file, encoding="latin-1").read()

    # nb: Only use the numeric values of https://docs.greenbone.net/GSM-Manual/gos-4/en/glossary.html#quality-of-detection-qod
    check_qod_num_values = [
        "1",
        "30",
        "50",
        "70",
        "75",
        "80",
        "95",
        "97",
        "98",
        "99",
        "100",
    ]

    match_qod = re.search(
        "script_tag\s*\(\s*name\s*\:\s*[\"'](qod)[\"']\s*\,\s*value\s*\:\s*([\"']([0-9]+)[\"'])",
        text,
    )
    match_qod_type = re.search(
        "script_tag\s*\(\s*name\s*\:\s*[\"'](qod_type)[\"']\s*\,\s*value\s*\:\s*[\"']([a-z\_]+)[\"']",
        text,
    )

    match_qod_wrong = re.search(
        "script_tag\s*\(\s*name\s*\:\s*[\"'](qod)[\"']\s*\,\s*value\s*\:\s*([0-9]+)",
        text,
    )
    match_qod_type_wrong = re.search(
        "script_tag\s*\(\s*name\s*\:\s*[\"'](qod_type)[\"']\s*\,\s*value\s*\:\s*([a-z\_]+)",
        text,
    )

    if match_qod and match_qod_type:
        return (
            -1,
            "VT '"
            + str(file)
            + "' consists of QoD type AND numeric value. Only use one, not both!",
        )

    if match_qod_wrong and match_qod_wrong.group(0) is not None:
        return (
            -1,
            "VT '"
            + str(file)
            + '\' has a QoD tag where the numeric value is not wrapped around "".',
        )

    if match_qod_type_wrong and match_qod_type_wrong.group(0) is not None:
        return (
            -1,
            "VT '"
            + str(file)
            + '\' has a QoD tag where the tag is not wrapped around "".',
        )

    if match_qod is not None or match_qod_type is not None:
        if (
            match_qod_type
            and match_qod_type.group(1)
            and match_qod_type.group(2)
        ):
            qod_type = match_qod_type.group(2)

            # List of valid qod_types, from highest QoD to lowest
            valid_qod_types = [
                "exploit",
                "remote_vul",
                "remote_app",
                "package",
                "registry",
                "remote_active",
                "remote_banner",
                "executable_version",
                "remote_analysis",
                "remote_probe",
                "remote_banner_unreliable",
                "executable_version_unreliable",
                "general_note",
            ]

            for valid_qod_type in valid_qod_types:
                if qod_type == valid_qod_type:
                    return (0,)

            return (
                -1,
                "VT '"
                + str(file)
                + "' is using an invalid or misspelled qod_type!",
            )

        if (
            match_qod
            and match_qod.group(1)
            and match_qod.group(2)
            and match_qod.group(3)
        ):
            qod_value = int(match_qod.group(3))
            for check in check_qod_num_values:
                if qod_value == int(check):
                    return (0,)
            return -1, "VT '" + str(
                file
            ) + "' is using an invalid qod value! Please only use one of the following numeric values: " + ", ".join(
                check_qod_num_values
            )

            # nb: Old code to only check for a range between 0 and 100
            # if 0 <= int(qod_value) <= 100:
            #    return 0,
            #
            # return -1, "VT '" + str(file) + "' is using an invalid qod value! Please only use a value between \"0\" and \"100\"."

    return (
        -1,
        "VT '"
        + str(file)
        + "' is missing a qod or qod_type or using incorrect values!",
    )


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = is_qod_correct(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report(
            "VTs using multiple QoD expressions or an invalid QoD type/value",
            error,
        )
        sys.exit(1)

    sys.exit(0)

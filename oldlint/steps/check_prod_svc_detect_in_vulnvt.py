#!/usr/bin/env python3

import re
import sys


def run(file):
    """This script checks if the passed VT if it is doing a vulnerability reporting and a product / service
    detection together in a single VT. More specific this step is checking and reporting VTs having a severity
    but are placed in these Families:

    - script_family("Product detection");
    - script_family("Service detection");

    and / or are using one of the following functions:

    - register_product()
    - register_and_report_os()
    - register_and_report_cpe()
    - register_host_detail()
    - service_register()
    - service_report()
    - build_cpe()
    - build_detection_report()
    - report_host_detail_single()
    - report_host_details()
    - report_best_os_cpe()
    - report_best_os_txt()

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message

    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    text = open(file, encoding="latin-1").read()

    # Don't need to check VTs having a cvss of 0.0
    cvss_detect = re.search(
        'script_tag\s*\(name\s*:\s*"cvss_base",\s*value:\s*"(\d{1,2}\.\d)"',
        text,
    )
    if cvss_detect is not None and cvss_detect.group(1) == "0.0":
        return (0,)

    match_family = re.search(
        'script_family\s*\("(Product|Service) detection"\s*\)\s*;', text
    )
    if match_family is not None and match_family.group(1) is not None:
        report = (
            "VT '"
            + str(file)
            + "' has a severity but is placed in the following family which is disallowed for such a VT:\n\n"
            + match_family.group(0)
            + "\n\n"
        )
        report += "Please split this VT into a separate Product / Service detection and Vulnerability-VT.\n"
        return -1, report

    found_funcs = ""

    match_funcs = re.finditer(
        "(register_(product|and_report(os|cpe)|host_detail)|service_(register|report)|build_(cpe|detection_report)|report_(host_(detail_single|details)|best_os_(cpe|txt)))\s*\([^)]*\)\s*;",
        text,
        re.MULTILINE,
    )
    if match_funcs is not None:
        for match_func in match_funcs:
            if "detected_by" not in match_func.group(
                0
            ) and "detected_at" not in match_func.group(0):
                found_funcs += "\n\t" + match_func.group(0)

    if len(found_funcs) > 0:
        report = (
            "VT '"
            + str(file)
            + "' has a severity but is using one of the following functions which is disallowed for such a VT:\n"
            + found_funcs
            + "\n\n"
        )
        report += "Please split this VT into a separate Product / Service detection and Vulnerability-VT.\n"
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
            "Vulnerability-VTs which are doing a product / service detection",
            error,
        )
        sys.exit(1)

    sys.exit(0)

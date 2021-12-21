#!/usr/bin/env python3

import re, os
import sys


def has_valid_url_script_xref(file):
    """
    Checks a given file if any of the script_xref(name:"URL", value:"") tags has not a valid value. Valid in the meaning of:

    - starts with a http://, https://, ftp:// or ftps:// link
    - doesn't contain a space/tab/newline somewhere in between (TBD: check for other invalid chars as well?)

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
    found_tags = ""
    req_start_re = re.compile("^((http|ftp)s?://)")
    disallow_re = re.compile("(\s+)")

    tag_matches = re.finditer(
        '(script_xref\(name\s*:\s*"URL"\s*,\s*value\s*:\s*")([^"]+)"',
        text,
        re.MULTILINE,
    )
    if tag_matches is not None:
        for tag_match in tag_matches:
            if tag_match is not None and tag_match.group(2) is not None:
                req_start_match = re.search(req_start_re, tag_match.group(2))
                if req_start_match is None or req_start_match.group(1) is None:
                    found_tags += "\n\t" + tag_match.group(0).partition(",")[0]
                disallow_match = re.search(disallow_re, tag_match.group(2))
                if (
                    disallow_match is not None
                    and disallow_match.group(1) is not None
                ):
                    found_tags += "\n\t" + tag_match.group(0).partition(",")[0]

    if len(found_tags) > 0:
        return -1, "The following script_xref tags of VT '" + str(
            file
        ) + "' doesn't start with a http://, https://, ftp:// or ftps:// or using a newline, tab or space:" + str(
            found_tags
        )

    return (0,)


def has_trail_lead_newline_tab_space_tag(file):
    """
    Checks a given file if any of the following script tags:

    - script_tag(name:"solution", value:"");
    - script_tag(name:"qod_type", value:"");
    - script_tag(name:"cvss_base", value:"");
    - script_tag(name:"cvss_base_vector", value:"");
    - script_tag(name:"summary", value:"");
    - script_tag(name:"last_modification", value:"");
    - script_tag(name:"insight", value:"");
    - script_tag(name:"affected", value:"");
    - script_tag(name:"creation_date", value:"");
    - script_tag(name:"vuldetect", value:"");
    - script_tag(name:"impact", value:"");
    - script_tag(name:"deprecated", value:"");
    - script_tag(name:"qod", value:"");
    - script_tag(name:"severity_vector", value:"");
    - script_tag(name:"severity_origin", value:"");
    - script_tag(name:"severity_date", value:"");
    - script_tag(name:"solution_method", value:""); # nb: Not fully implemented in GVM yet (further implementation "on hold").

    contains a leading and/or trailing newline, tab or space within the value string.

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
    found_tags = ""

    # TODO: Maybe merge these into one single (clever) regex
    tag_matches = re.finditer(
        '(script_tag\(name\s*:\s*"(solution|solution_type|qod_type|cvss_base|cvss_base_vector|summary|last_modification|insight|affected|creation_date|vuldetect|impact|deprecated|qod|severity_vector|severity_origin|severity_date|solution_method)"\s*,\s*value\s*:\s*")([^"]+)"',
        text,
    )
    if tag_matches is not None:
        for match in tag_matches:
            if match is not None and match.group(3) is not None:
                for to_check in (r"\n", r"\t", " "):
                    if match.group(3).startswith(to_check) or match.group(
                        3
                    ).endswith(to_check):

                        # False positive due to the following string:
                        # then next " + lookahead + " days."
                        if (
                            "gb_ssl_tls_cert_in_chain_soonexpired.nasl" in file
                            and 'script_tag(name:"insight"' in match.group(0)
                        ):
                            continue

                        found_tags += "\n\t" + match.group(0).partition(",")[0]

    tag_matches = re.finditer(
        '(script_xref\(name\s*:\s*"[^"]+"\s*,\s*value\s*:\s*")([^"]+)"', text
    )
    if tag_matches is not None:
        for match in tag_matches:
            if match is not None and match.group(2) is not None:
                for to_check in (r"\n", r"\t", " "):
                    if match.group(2).startswith(to_check) or match.group(
                        2
                    ).endswith(to_check):
                        found_tags += "\n\t" + match.group(0).partition(",")[0]

    if len(found_tags) > 0:
        return -1, "The following script_tags of VT '" + str(
            file
        ) + "' using a leading and/or trailing newline, tab or space:" + str(
            found_tags
        )

    return (0,)


def has_valid_script_tag_calls(file):
    """This script checks for the validity in a form of name: / value: of the following:

    - script_tag(name:"name", value:"value");
    - script_xref(name:"name", value:"value");

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message

    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    report = ""

    calls_to_check = ["tag", "xref"]
    with open(file, "rt", encoding="latin-1") as f:
        for line in f:
            if line.strip().startswith("#"):
                # Skip commented lines
                continue

            call_result = re.search(
                "script_(" + "|".join(calls_to_check) + ").*", line
            )
            if call_result is not None and call_result.group(0) is not None:
                match_result = re.search(
                    "script_("
                    + "|".join(calls_to_check)
                    + ')\s*\(\s*name\s*:\s*".*"\s*\,\s*value\s*:\s*',
                    call_result.group(0),
                )
                if match_result is None or match_result.group(0) is None:
                    report += line + "\r\n"

    if len(report) > 0:
        report = (
            "%s doesn't contain the required 'name:, value:' syntax at the following line(s):\r\n\r\n"
            % file
            + report
        )
        return -1, report
    return (0,)


def has_recommended_script_calls(file):
    """This script checks for the existence of recommended script calls like

    - script_dependencies
    - script_require_ports
    - script_require_udp_ports
    - script_require_keys
    - script_mandatory_keys

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
                1 => Success, with debug messages

    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    recommended_single_call = ["dependencies"]
    recommended_single = False
    recommended_many_calls = [
        "require_ports",
        "require_udp_ports",
        "require_keys",
        "mandatory_keys",
    ]
    recommended_many = False
    recommended_ignore = False
    with open(file, "rt", encoding="latin-1") as f:
        for line in f:
            if line.strip().startswith("#"):
                # Skip commented lines
                continue

            # Don't report the recommend calls for VTs in this category
            ign = re.search(
                "script_category\(ACT_(SETTINGS|SCANNER|INIT)\)", line
            )
            if ign is not None:
                recommended_ignore = True
                break

            # Avoid unnecessary message against deprecated VTs.
            ign = re.search(
                'script_tag\s*\(\s*name\s*:\s*"deprecated"\s*,\s*value\s*:\s*TRUE\s*\)\s*;',
                line,
            )
            if ign is not None:
                recommended_ignore = True
                break

            if not recommended_single:
                rsc = re.search(
                    "script_(" + "|".join(recommended_single_call) + ")", line
                )
                if rsc is not None:
                    recommended_single = True

            if not recommended_many:
                rmc = re.search(
                    "script_(" + "|".join(recommended_many_calls) + ")", line
                )
                if rmc is not None:
                    recommended_many = True

            if recommended_many and recommended_single:
                return (0,)

    if recommended_ignore:
        return (0,)

    report = ""

    if not recommended_single:
        report += (
            "%s does not call the following recommended procedure: " % file
        )
        for call in recommended_single_call:
            report += "\r\n - script_" + call

    if not recommended_many:
        if not recommended_single:
            report += "\r\n\r\n"
        report += (
            "%s does not call one of the following recommended procedure(s): "
            % file
        )
        for call in recommended_many_calls:
            report += "\r\n - script_" + call

    return 1, report


def has_all_mandatory_script_calls(file):
    """This script checks for the existence of mandatory script calls like

    - script_name
    - script_version
    - script_category
    - script_family
    - script_copyright

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message

    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    mandatory_calls = ["name", "version", "category", "family", "copyright"]
    with open(file, "rt", encoding="latin-1") as f:
        for line in f:
            if not mandatory_calls:
                break
            if line.strip().startswith("#"):
                # Skip commented lines
                continue
            mc = re.search("script_(" + "|".join(mandatory_calls) + ")", line)
            if mc is not None:
                mandatory_calls.remove(mc.group(1))

    if len(mandatory_calls) == 0:
        return (0,)

    err = "%s does not call the following mandatory procedure(s): " % file
    for call in mandatory_calls:
        err += "\r\n - script_" + call
    return -1, err


def has_all_mandatory_script_tags(file):
    """This script checks for the existence of mandatory script tags like

    - script_tag(name:"summary"

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message

    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    mandatory_tags = ["summary"]
    with open(file, "rt", encoding="latin-1") as f:
        for line in f:
            if not mandatory_tags:
                break
            if line.strip().startswith("#"):
                # Skip commented lines
                continue
            mt = re.search(
                'script_tag\s*\(\s*name\s*:\s*"('
                + "|".join(mandatory_tags)
                + ")",
                line,
            )
            if mt is not None:
                mandatory_tags.remove(mt.group(1))

    if len(mandatory_tags) == 0:
        return (0,)

    err = "%s does not call the following mandatory procedure(s): " % file
    for tag in mandatory_tags:
        err += '\r\n - script_tag(name:"' + tag + '"'
    return -1, err


def has_empty_values(file):
    """This script checks for empty 'value:""' in the script tags.
    Excepted from this is script_add_preference().

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message
    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    report = ""

    with open(file, "rt", encoding="latin-1") as f:
        for line in f:
            # Checking both single and double quotes until the QA is checking the description for a stricter syntax
            empty_value_matches = re.search(
                ".*value\s*:\s*(\"\s*\"|'\s*')\s*\)\s*;", line
            )
            if (
                empty_value_matches is not None
                and empty_value_matches.group(1) is not None
                and "script_add_preference" not in empty_value_matches.group(0)
            ):
                report += "\r\n" + empty_value_matches.group(0)

    if len(report) > 0:
        return -1, "The VT '" + str(
            file
        ) + "' consists of one or multiple script tags with empty values:" + str(
            report
        )

    return (0,)


if __name__ == "__main__":
    import ci_helpers

    exit_error = False

    valid_url_script_xref_errors = []
    trail_lead_newline_tab_space_tag_errors = []
    valid_script_tag_calls_errors = []
    all_mandatory_script_calls_errors = []
    all_mandatory_script_tags_errors = []
    empty_values_errors = []
    recommended_script_calls_debug = []

    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = has_valid_url_script_xref(file)
            if test[0] != 0:
                valid_url_script_xref_errors.append(file)

            test = has_trail_lead_newline_tab_space_tag(file)
            if test[0] != 0:
                trail_lead_newline_tab_space_tag_errors.append(file)

            test = has_valid_script_tag_calls(file)
            if test[0] != 0:
                valid_script_tag_calls_errors.append(file)

            test = has_all_mandatory_script_calls(file)
            if test[0] != 0:
                all_mandatory_script_calls_errors.append(file)

            test = has_all_mandatory_script_tags(file)
            if test[0] != 0:
                all_mandatory_script_tags_errors.append(file)

            test = has_empty_values(file)
            if test[0] != 0:
                empty_values_errors.append(file)

            test = has_recommended_script_calls(file)
            if test[0] != 0:
                recommended_script_calls_debug.append(file)

    else:
        sys.exit(0)

    if len(valid_url_script_xref_errors) > 0:
        ci_helpers.report(
            "Files having invalid xref tag", valid_url_script_xref_errors
        )
        exit_error = True

    if len(trail_lead_newline_tab_space_tag_errors) > 0:
        ci_helpers.report(
            "Files using a leading and/or trailing newline, tab or space in script_tags",
            trail_lead_newline_tab_space_tag_errors,
        )
        exit_error = True

    if len(valid_script_tag_calls_errors) > 0:
        ci_helpers.report(
            "Files with script_tags not containing the required 'name:, value:' syntax",
            valid_script_tag_calls_errors,
        )
        exit_error = True

    if len(all_mandatory_script_calls_errors) > 0:
        ci_helpers.report(
            "Files not calling all mandatory script_CALL",
            all_mandatory_script_calls_errors,
        )
        exit_error = True

    if len(all_mandatory_script_tags_errors) > 0:
        ci_helpers.report(
            "Files not calling all mandatory script_tags",
            all_mandatory_script_tags_errors,
        )
        exit_error = True

    if len(empty_values_errors) > 0:
        ci_helpers.report(
            "Files having one or multiple script tags with empty values",
            empty_values_errors,
        )
        exit_error = True

    if len(recommended_script_calls_debug) > 0:
        ci_helpers.report(
            "Files not calling all of the recommended procedure",
            recommended_script_calls_debug,
        )

    if exit_error:
        sys.exit(1)

    sys.exit(0)

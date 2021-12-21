#!/usr/bin/env python3

import re
import sys


def is_family_correct(file):
    """The script checks the passed VT for the existence / validity of its script family with the help of regular expression.
    An error will be thrown if the VT does not contain of a script_family at all or if the used script_family is misspelled or invalid.

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
    match = re.search('script_family\("([0-9A-Za-z\s\-:\.]*)', text)

    if match is None or match.group(1) is None:
        return -1, "VT '" + str(file) + "' is missing a script family!"

    family = match.group(1)

    # List of valid script_families, in alphabetical order
    valid_families = [
        "AIX Local Security Checks",
        "Amazon Linux Local Security Checks",
        "Brute force attacks",
        "Buffer overflow",
        "CISCO",
        "CentOS Local Security Checks",
        "Citrix Xenserver Local Security Checks",
        "Compliance",
        "Credentials",
        "Databases",
        "Debian Local Security Checks",
        "Default Accounts",
        "Denial of Service",
        "F5 Local Security Checks",
        "FTP",
        "Fedora Local Security Checks",
        "FortiOS Local Security Checks",
        "FreeBSD Local Security Checks",
        "Gain a shell remotely",
        "General",
        "Gentoo Local Security Checks",
        "Huawei",
        "Huawei EulerOS Local Security Checks",
        "HP-UX Local Security Checks",
        "IT-Grundschutz",
        "IT-Grundschutz-deprecated",
        "IT-Grundschutz-15",
        "JunOS Local Security Checks",
        "Mac OS X Local Security Checks",
        "Mageia Linux Local Security Checks",
        "Malware",
        "Mandrake Local Security Checks",
        "Nmap NSE",
        "Nmap NSE net",
        "Oracle Linux Local Security Checks",
        "PCI-DSS",
        "PCI-DSS 2.0",
        "Palo Alto PAN-OS Local Security Checks",
        "Peer-To-Peer File Sharing",
        "Policy",
        "Port scanners",
        "Privilege escalation",
        "Product detection",
        "RPC",
        "Red Hat Local Security Checks",
        "Remote file access",
        "SMTP problems",
        "SNMP",
        "SSL and TLS",
        "Service detection",
        "Settings",
        "Slackware Local Security Checks",
        "Solaris Local Security Checks",
        "SuSE Local Security Checks",
        "Ubuntu Local Security Checks",
        "Useless services",
        "VMware Local Security Checks",
        "Web Servers",
        "Web application abuses",
        "Windows",
        "Windows : Microsoft Bulletins",
    ]

    for valid_family in valid_families:
        if family == valid_family:
            return (0,)

    return (
        -1,
        "VT '"
        + str(file)
        + "' is using an invalid or misspelled script family!",
    )


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = is_family_correct(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report(
            "VTs using an invalid or misspelled script family", error
        )
        sys.exit(1)

    sys.exit(0)

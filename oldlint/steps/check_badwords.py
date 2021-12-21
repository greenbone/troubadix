#!/usr/bin/env python3

import re
import sys


def has_badword(file):
    """This script checks the passed VT for the use of any of the defined badwords with the help of regular expression.
    An error will be thrown if the VT contains such a badword.

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message

    """

    # |hexstr(OpenVAS)|hexstr(openvas)
    badwords = ".*(cracker|openvas|4f70656e564153|6f70656e766173).*"
    text = open(file, encoding="latin-1").read()
    badword_match = re.finditer(badwords, text, re.IGNORECASE)
    badword_found = False
    badword_report = (
        "VT/Include '"
        + str(file)
        + "' is matching the badword pattern '"
        + badwords
        + "' in the following line(s):\n"
    )

    if badword_match is not None:
        for line in badword_match:
            if line is not None and line.group(0) is not None:
                if "openvas-nasl" in line.group(0):
                    continue
                if "openvas-smb" in line.group(0):
                    continue
                if "openvassd" in line.group(0):
                    continue
                if line.group(0).startswith("# OpenVAS Vulnerability Test"):
                    continue
                if line.group(0).startswith("# OpenVAS Include File"):
                    continue
                if "lists.wald.intevation.org" in line.group(0):
                    continue
                if line.group(0).startswith("  script_"):
                    continue
                if "cpe:/a:openvas" in line.group(0):
                    continue
                if line.group(0).startswith("# $Id: "):
                    continue
                if (
                    "'OpenVAS Manager" in line.group(0)
                    or "OpenVAS Administrator" in line.group(0)
                    or "OpenVAS / Greenbone Vulnerability Manager"
                    in line.group(0)
                ):
                    continue
                if "gb_openvas" in file or "gb_openvas_" in line.group(0):
                    continue
                if "gb_gsa_" in file or "OpenVAS_detect.nasl" in file:
                    continue
                if (
                    "http_func.inc" in file
                    and "openvas" in line.group(0).lower()
                ):
                    continue
                if (
                    "misc_func.inc" in file
                    and "openvas" in line.group(0).lower()
                ):
                    continue
                if "OPENVAS_VERSION" in line.group(0):
                    continue
                if "openvas.org" in line.group(0):
                    continue
                if "get_preference" in line.group(0):
                    continue
                if "OPENVAS_USE_LIBSSH" in line.group(0):
                    continue
                if "github.com/greenbone" in line.group(0):
                    continue
                # Some fedora package names as used in e.g. isrpmvuln()
                if (
                    "openvas-libraries" in line.group(0)
                    or "openvas-scanner" in line.group(0)
                    or "openvas-gsa" in line.group(0)
                    or "openvas-cli" in line.group(0)
                    or "openvas-manager" in line.group(0)
                ):
                    continue
                # Just OpenVAS versions which are "real"
                if "find_service3.nasl" in file and "OpenVAS-" in line.group(0):
                    continue
                if "OpenVAS_detect.nasl" in line.group(0):
                    continue
                # This scanner internal function is still called like this
                if "OpenVAS TCP Scanner" in line.group(
                    0
                ) or "openvas_tcp_scanner" in line.group(0):
                    continue
                # Currently can't be changed because the affect of the detection is unknown.
                if "Cookie: mstshash=openvas" in line.group(0):
                    continue
                # Currently unclear if changing these strings are affecting the SMB functionality
                # or the crafted SMB binary requests so they should be left for now.
                if "smb_nt.inc" in file and "lanman" in line.group(0):
                    continue

                badword_report = badword_report + line.group(0) + "\n"
                badword_found = True

    if badword_found:
        return -1, badword_report

    return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = has_badword(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report(
            "VTs/Includes matching badword pattern '.*(cracker|openvas|4f70656e564153|6f70656e766173).*'",
            error,
        )
        sys.exit(1)

    sys.exit(0)

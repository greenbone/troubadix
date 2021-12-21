#!/usr/bin/env python3

import re, os
import sys


def run(file):
    """This steps checks if a VT contains a Copyright statement
         containing a year not matching the year defined in the
         creation_date statement like script_tag(name:"creation_date", value:"2017-

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

    report = ""
    crdate = ""
    cryear = ""
    crdict = {}

    with open(file, "rt", encoding="latin-1") as f:
        for line in f:

            if "creation_date" in line:
                expre = re.search('value\s*:\s*"(.*)"', line)
                if expre is not None and expre.group(1) is not None:
                    crdate = expre.group(1)
                    expre = re.search("^([0-9]+)-", crdate)
                    if expre is not None and expre.group(1) is not None:
                        cryear = expre.group(1)

            copyright = re.search(
                "(# |script_copyright.*)[Cc]opyright \([Cc]\) ([0-9]+)", line
            )
            if (
                copyright is not None
                and copyright.group(2) is not None
                and "sw_telnet_os_detection.nasl" not in file
                and "gb_hp_comware_platform_detect_snmp.nasl" not in file
                and "gb_hirschmann_telnet_detect.nasl" not in file
            ):
                crdict[line] = copyright.group(2)

        if cryear == "":
            return (
                1,
                "Missing creation_date statement in VT '"
                + str(file)
                + "'. Step can't continue!",
            )

        # key is the line where the copyright is found, value the year found within that line
        for key, value in list(crdict.items()):
            if value != cryear:
                report += "\n" + key.strip() + "\n"

    if len(report) > 0:
        report = (
            "VT '" + str(file) + "' contains a Copyright year not matching "
            "the year in " + crdate + " at the following lines:\n" + report
        )
        return -1, report
    return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            if "pre2008/" in file:
                continue
            test = run(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report(
            "VTs containing a Copyright year not matching the creation date",
            error,
        )
        sys.exit(1)

    sys.exit(0)

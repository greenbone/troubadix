#!/usr/bin/env python3

import re
import sys


def run(file):
    """
    Checks a given file if it is accessing one or more "Services/" KB keys like e.g.

    get_kb_item("Services/www");
    get_kb_list("Services/udp/upnp");

    These calls should use a "wrapping" function like e.g. the following (depending on the Service KB key) instead:

    http_get_port()
    service_get_port()
    service_get_ports()

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

    services_kb_accessed = ""

    kb_matches = re.finditer(
        "(get_kb_(item|list)\s*\(\s*[\"']Services/[^)]+\))", text
    )
    if kb_matches is not None:
        for kb_match in kb_matches:
            if kb_match is not None and kb_match.group(1) is not None:
                # special cases where not function currently exists
                if "Services/tcp/*" in kb_match.group(
                    1
                ) or "Services/udp/*" in kb_match.group(1):
                    continue

                # another special case, the find_service*.nasl need to access "Services/unknown" directly.
                # The same is valid for unknown_services.nasl as well.
                if "unknown_services.nasl" in file or re.search(
                    "find_service([0-9]+|_(3digits|spontaneous|nmap|nmap_wrapped))?\.nasl",
                    file,
                ):
                    continue

                # an additional special case, this needs to access the KB key directly
                if "2017/gb_hp_printer_rce_vuln.nasl" in file:
                    continue

                services_kb_accessed += "\n\t" + kb_match.group(1)

    if len(services_kb_accessed) > 0:
        return -1, "The following get_kb_item() / get_kb_list() call(s) of VT '" + str(
            file
        ) + "' should use a function instead of a direct access to the 'Services/' KB key:" + str(
            services_kb_accessed
        )

    else:
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
            "VTs which should use a function instead of a direct access to the 'Services/' KB key",
            error,
        )
        sys.exit(1)

    sys.exit(0)

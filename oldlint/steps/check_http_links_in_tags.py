#!/usr/bin/env python3

import re
import sys


def contains_http_link_in_tag(file):
    """
    Checks a given file if any of the script_tag(name:"(summary|impact|affected|insight|vuldetect|solution)", value:"")
    contains a http(s)://, ftp:(s)://, ftp. and/or www. link which should be moved to the following tag instead:

    script_xref(name:"URL", value:"");

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
    tag_matches = re.finditer(
        '(script_tag\(name\s*:\s*"(summary|impact|affected|insight|vuldetect|solution)"\s*,\s*value\s*:\s*")([^"]+)"',
        text,
    )
    http_link_tags = ""
    if tag_matches is not None:
        for tag_match in tag_matches:
            if tag_match is not None and tag_match.group(3) is not None:
                http_link_matches = re.finditer(
                    ".*((http|ftp)s?://|(www|\s+ftp)\.).*", tag_match.group(3)
                )
                if http_link_matches is not None:
                    for http_link_match in http_link_matches:
                        if (
                            http_link_match is not None
                            and http_link_match.group(1) is not None
                        ):
                            if (
                                "The payloads try to open a connection to www.google.com"
                                in http_link_match.group(0)
                            ):
                                continue
                            if (
                                "The script attempts to connect to www.google.com"
                                in http_link_match.group(0)
                            ):
                                continue
                            if (
                                "to retrieve a web page from www.google.com"
                                in http_link_match.group(0)
                            ):
                                continue
                            if (
                                "Subject: commonName=www.paypal.com"
                                in http_link_match.group(0)
                            ):
                                continue
                            if (
                                "Terms of use at https://www.verisign.com/rpa"
                                in http_link_match.group(0)
                            ):
                                continue
                            if "example.com" in http_link_match.group(
                                0
                            ) or "example.org" in http_link_match.group(0):
                                continue
                            if "www.exam" in http_link_match.group(0):
                                continue
                            if (
                                "sampling the resolution of a name (www.google.com)"
                                in http_link_match.group(0)
                            ):
                                continue
                            if (
                                "once with 'www.' and once without"
                                in http_link_match.group(0)
                            ):
                                continue
                            if (
                                "wget http://www.javaop.com/~ron/tmp/nc"
                                in http_link_match.group(0)
                            ):
                                continue
                            if (
                                "Ncat: Version 5.30BETA1 (http://nmap.org/ncat)"
                                in http_link_match.group(0)
                            ):
                                continue
                            if (
                                "as www.windowsupdate.com. (BZ#506016)"
                                in http_link_match.group(0)
                            ):
                                continue
                            if (
                                "located at http://sambarserver/session/pagecount."
                                in http_link_match.group(0)
                            ):
                                continue
                            if "http://rest.modx.com" in http_link_match.group(
                                0
                            ):
                                continue
                            if (
                                "ftp:// " in http_link_match.group(0)
                                or "ftp://'" in http_link_match.group(0)
                                or "ftp://)" in http_link_match.group(0)
                                or "ftp.c" in http_link_match.group(0)
                                or "ftp.exe" in http_link_match.group(0)
                            ):
                                continue
                            if (
                                "using special ftp://"
                                in http_link_match.group(0)
                                or "running ftp." in http_link_match.group(0)
                                or "ftp. The vulnerability"
                                in http_link_match.group(0)
                            ):
                                continue
                            if "'http://' protocol" in http_link_match.group(
                                0
                            ) or "handle <a href='http://...'> properly" in http_link_match.group(
                                0
                            ):
                                continue
                            if (
                                "Switch to git+https://"
                                in http_link_match.group(0)
                            ):
                                continue
                            if (
                                "wget https://compromised-domain.com/important-file"
                                in http_link_match.group(0)
                            ):
                                continue
                            if "the https:// scheme" in http_link_match.group(
                                0
                            ):
                                continue
                            if (
                                "https://www.phishingtarget.com@evil.com"
                                in http_link_match.group(0)
                            ):
                                continue
                            http_link_tags += (
                                "\n\t"
                                + tag_match.group(0).partition(",")[0]
                                + ", link: "
                                + http_link_match.group(0)
                            )

    if len(http_link_tags) > 0:
        return (
            -1,
            "The following script_tags of VT '"
            + str(file)
            + '\' are using an HTTP Link/URL which should be moved to a separate \'script_xref(name:"URL", value:"");\' tag instead:'
            + http_link_tags,
        )

    return (0,)


def contains_nvd_mitre_link_in_xref(file):
    """
    Checks a given file if the script_xref(name:"URL", value:""); contains a link to an URL including any of this occurrence:

    - https://nvd.nist.gov/vuln/detail/CVE-

    - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-

    Background: Both links are already covered by the script_cve_id() tag and the Link is just a redundant information.

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
    tag_matches = re.finditer(
        '(script_xref\(name\s*:\s*"URL"\s*,\s*value\s*:\s*")([^"]+)"', text
    )
    nvd_mitre_link_tags = ""
    if tag_matches is not None:
        for match in tag_matches:
            if match is not None and match.group(2) is not None:
                if "nvd.nist.gov/vuln/detail/CVE-" in match.group(
                    2
                ) or "cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-" in match.group(
                    2
                ):
                    nvd_mitre_link_tags += "\n\t" + match.group(0)

    if len(nvd_mitre_link_tags) > 0:
        return (
            -1,
            "The following script_xref of VT '"
            + str(file)
            + "' is pointing to Mitre/NVD which is already covered by the script_cve_id. This is a redundant info and the script_xref needs to be removed:"
            + nvd_mitre_link_tags,
        )

    return (0,)


if __name__ == "__main__":
    import ci_helpers

    link_in_tag = []
    mitre_in_xref = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            http_link_in_tag = contains_http_link_in_tag(file)
            nvd_mitre_link_in_xref = contains_nvd_mitre_link_in_xref(file)
            if http_link_in_tag[0] != 0:
                link_in_tag.append(file)
            if nvd_mitre_link_in_xref[0] != 0:
                mitre_in_xref.append(file)

    else:
        sys.exit(0)

    if len(link_in_tag) > 0:
        ci_helpers.report(
            "VTs containing a http(s)://, ftp:(s)://, ftp. and/or www. link in a tag",
            link_in_tag,
        )

    if len(mitre_in_xref) > 0:
        ci_helpers.report(
            "VTs with nvd.nist.gov or cve.mitre.org in script_xref tag",
            mitre_in_xref,
        )

    if len(link_in_tag) > 0 or len(mitre_in_xref) > 0:
        sys.exit(1)

    sys.exit(0)

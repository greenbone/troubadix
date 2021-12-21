#!/usr/bin/env python3

import re
import sys


def has_valid_oid(file):
    """Checks if a NASL script is using a valid script_oid() tag.

    Valid:
    script_oid("1.3.6.1.4.1.25623.1.0.12345");
    script_oid('1.3.6.1.4.1.25623.1.0.12345');
    Any of the OID ranges mentioned in https://intra.greenbone.net/Production/GSF#All_ID_ranges

    Not valid:
    script_oid(""); (no OID included)
    script_oid(); (empty tag)
    script_oid("1.3.6.1.4.1.25623.1.12345"); (malformed)
    A OID range not mentioned in https://intra.greenbone.net/Production/GSF#All_ID_ranges

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
    oid_match = re.search(
        "^\s*script_oid\s*\(\s*[\"']([0-9.]+)[\"']\s*\)\s*;", text, re.MULTILINE
    )
    if oid_match is None or oid_match.group(1) is None:
        return -1, "No valid script_oid() call found in VT '" + str(file) + "'"

    oid = oid_match.group(1)

    if "1.3.6.1.4.1.25623.1." not in oid:
        return (
            -1,
            "script_oid() in VT '"
            + str(file)
            + "' is using an invalid OID '"
            + str(oid)
            + "'",
        )

    # Vendor-specific OIDs
    if "1.3.6.1.4.1.25623.1.1" in oid:
        family_match = re.search(
            "^\s*script_family\s*\(\s*[\"']([0-9A-Za-z\s\-:\.]+)[\"']\s*\)\s*;",
            text,
            re.MULTILINE,
        )
        if family_match is None or family_match.group(1) is None:
            return -1, "VT '" + str(file) + "' is missing a script family!"
        family = family_match.group(1)

        # Fixed OID-scheme for (Huawei) Euler OS OIDs
        if "1.3.6.1.4.1.25623.1.1.2." in oid:
            if family != "Huawei EulerOS Local Security Checks":
                return (
                    -1,
                    "VT '"
                    + str(file)
                    + "' is using an OID that is reserved for EulerOS VTs '"
                    + str(oid)
                    + "'",
                )
            euler_sa_match = re.search(
                "^1\.3\.6\.1\.4\.1\.25623\.1\.1\.2\.20[0-4][0-9]\.[0-9]{4}$",
                oid,
            )
            if euler_sa_match is None:
                return (
                    -1,
                    "script_oid() in VT '"
                    + str(file)
                    + "'is using an invalid OID '"
                    + str(oid)
                    + "' (EulerOS pattern: 1.3.6.1.4.1.25623.1.1.2.[ADVISORY_YEAR].[ADVISORY_ID])",
                )
            return (0,)
        # Fixed OID-scheme for SUSE SLES OS OIDs
        elif "1.3.6.1.4.1.25623.1.1.4." in oid:
            if family != "SuSE Local Security Checks":
                return (
                    -1,
                    "VT '"
                    + str(file)
                    + "' is using an OID that is reserved for SUSE SLES VTs '"
                    + str(oid)
                    + "'",
                )
            sles_sa_match = re.search(
                "^1\.3\.6\.1\.4\.1\.25623\.1\.1\.4\.20[0-4][0-9]\.[0-9]{4,5}\.[0-9]$",
                oid,
            )
            if sles_sa_match is None:
                return (
                    -1,
                    "script_oid() in VT '"
                    + str(file)
                    + "'is using an invalid OID '"
                    + str(oid)
                    + "' (SLES pattern: 1.3.6.1.4.1.25623.1.1.4.[ADVISORY_YEAR].[ADVISORY_ID].[ADVISORY_REVISION])",
                )
            return (0,)
        else:
            vendor_number_match = re.search(
                "^1\.3\.6\.1\.4\.1\.25623\.1\.1\.([0-9]+)\.", oid
            )
            if (
                vendor_number_match is None
                or vendor_number_match.group(1) is None
            ):
                return (
                    -1,
                    "script_oid() in VT '"
                    + str(file)
                    + "'is using an invalid OID '"
                    + str(oid)
                    + "' (last digits)",
                )

            # https://gitlab.greenbone.net/tpassfeld/next-gen-lsc-poc/blob/4b576e4af40614ac29d1dc8f341026fb5f39d5db/generator/config.cfg#L9-21
            vendor_number = vendor_number_match.group(1)

            if vendor_number == "1":
                if family != "Debian Local Security Checks":
                    return (
                        -1,
                        "VT '"
                        + str(file)
                        + "' is using an OID that is reserved for Debian VTs '"
                        + str(oid)
                        + "'",
                    )

            elif vendor_number == "3":
                if family != "CentOS Local Security Checks":
                    return (
                        -1,
                        "VT '"
                        + str(file)
                        + "' is using an OID that is reserved for CentOS VTs '"
                        + str(oid)
                        + "'",
                    )

            elif vendor_number == "4":
                if family != "CentOS Local Security Checks":
                    return (
                        -1,
                        "VT '"
                        + str(file)
                        + "' is using an OID that is reserved for CentOS_CR VTs '"
                        + str(oid)
                        + "'",
                    )

            elif vendor_number == "5":
                if family != "Fedora Local Security Checks":
                    return (
                        -1,
                        "VT '"
                        + str(file)
                        + "' is using an OID that is reserved for Fedora VTs '"
                        + str(oid)
                        + "'",
                    )

            elif vendor_number == "6":
                if family != "Gentoo Local Security Checks":
                    return (
                        -1,
                        "VT '"
                        + str(file)
                        + "' is using an OID that is reserved for Gentoo VTs '"
                        + str(oid)
                        + "'",
                    )

            elif vendor_number == "7":
                if family != "HP-UX Local Security Checks":
                    return (
                        -1,
                        "VT '"
                        + str(file)
                        + "' is using an OID that is reserved for HP-UX VTs '"
                        + str(oid)
                        + "'",
                    )

            elif vendor_number == "8":
                if family != "Mandrake Local Security Checks":
                    return (
                        -1,
                        "VT '"
                        + str(file)
                        + "' is using an OID that is reserved for Mandrake/Mandriva VTs '"
                        + str(oid)
                        + "'",
                    )

            elif vendor_number == "9":
                if family != "SuSE Local Security Checks":
                    return (
                        -1,
                        "VT '"
                        + str(file)
                        + "' is using an OID that is reserved for openSUSE VTs '"
                        + str(oid)
                        + "'",
                    )

            elif vendor_number == "10":
                if family != "Red Hat Local Security Checks":
                    return (
                        -1,
                        "VT '"
                        + str(file)
                        + "' is using an OID that is reserved for Red Hat VTs '"
                        + str(oid)
                        + "'",
                    )

            elif vendor_number == "11":
                if family != "Solaris Local Security Checks":
                    return (
                        -1,
                        "VT '"
                        + str(file)
                        + "' is using an OID that is reserved for Solaris VTs '"
                        + str(oid)
                        + "'",
                    )

            elif vendor_number == "12":
                if family != "SuSE Local Security Checks":
                    return (
                        -1,
                        "VT '"
                        + str(file)
                        + "' is using an OID that is reserved for SUSE VTs '"
                        + str(oid)
                        + "'",
                    )

            elif vendor_number == "13":
                if family != "Ubuntu Local Security Checks":
                    return (
                        -1,
                        "VT '"
                        + str(file)
                        + "' is using an OID that is reserved for Ubuntu VTs '"
                        + str(oid)
                        + "'",
                    )
            else:
                return (
                    -1,
                    "VT '"
                    + str(file)
                    + "' is using an invalid OID '"
                    + str(oid)
                    + "' (Vendor OID with unknown Vendor-Prefix)",
                )

            return (0,)

    # product-specific OIDs
    if oid.startswith("1.3.6.1.4.1.25623.1.2."):
        name_match = re.search(
            "^\s*script_name\s*\(\s*[\"']([\w ()-]+)[\"']\s*\)\s*;",
            text,
            re.MULTILINE,
        )
        if not name_match or not name_match.group(1):
            return -1, "VT '" + str(file) + "' is missing a script name!"
        name = name_match.group(1)

        # Fixed OID-scheme for Mozilla Firefox OIDs
        if oid.startswith("1.3.6.1.4.1.25623.1.2.1."):
            if not name.startswith("Mozilla Firefox Security Advisory"):
                return (
                    -1,
                    "VT '"
                    + str(file)
                    + "' is using an OID that is reserved for Firefox VTs '"
                    + str(oid)
                    + "'",
                )
            firefox_sa_match = re.search(
                "^1\.3\.6\.1\.4\.1\.25623\.1\.2\.1\.20[1-4][0-9]\.[0-9]{2,3}$",
                oid,
            )
            if not firefox_sa_match:
                return (
                    -1,
                    "script_oid() in VT '"
                    + str(file)
                    + "'is using an invalid OID '"
                    + str(oid)
                    + "' (Firefox pattern: 1.3.6.1.4.1.25623.1.2.1.[ADVISORY_YEAR].[ADVISORY_ID])",
                )
            return (0,)

    oid_digit_match = re.search("^1\.3\.6\.1\.4\.1\.25623\.1\.0\.([0-9]+)", oid)
    if oid_digit_match is None or oid_digit_match.group(1) is None:
        return (
            -1,
            "script_oid() in VT '"
            + str(file)
            + "' is using an invalid OID '"
            + str(oid)
            + "' (last digits)",
        )

    # nb: Those are using invalid OID ranges but are already in the feed since longer time and can't be fixed / changed.
    if (
        "ossim_server_detect.nasl" in file
        or "gsf/2018/vmware/gb_vmware_fusion_vmxnet3_stack_memory_usage_vuln_macosx.nasl"
        in file
        or "2008/asterisk_sdp_header_overflow.nasl" in file
        or "2008/cisco_ios_ftp_server_auth_bypass.nasl" in file
        or "2008/qk_smtp_server_dos.nasl" in file
        or "2008/asterisk_pbx_guest_access_enabled.nasl" in file
        or "2008/asterisk_null_pointer_dereference.nasl" in file
        or "2008/goaheadwebserver_source_disclosure.nasl" in file
        or "2011/secpod_ibm_lotus_domino_rpc_auth_dos_vuln.nasl" in file
        or "2011/secpod_cubecart_mult_xss_and_sql_inj_vuln.nasl" in file
        or "2016/gb_adobe_air_mult_vuln_feb16_macosx.nasl" in file
        or "attic/gb_cybozu_garoon_mult_vuln_aug16.nasl" in file
        or "2017/gb_openssh_mult_vuln_jan17_lin.nasl" in file
        or "2017/gb_xenserver_ctx219378.nasl" in file
    ):
        return (0,)

    oid_digit = int(oid_digit_match.group(1))

    # See https://confluence.greenbone.net/display/GSFDEV/OID+Assignment for a list of valid/currently assigned OID ranges
    if (
        (oid_digit >= 10000 and oid_digit <= 29999)
        or (oid_digit >= 50000 and oid_digit <= 118999)
        or (oid_digit >= 120000 and oid_digit <= 123999)
        or (oid_digit >= 130000 and oid_digit <= 169999)
        or (oid_digit >= 200000 and oid_digit <= 209999)
        or (oid_digit >= 700000 and oid_digit <= 919999)
        or (oid_digit >= 1020000 and oid_digit <= 1029999)
    ):
        return (0,)

    if oid_digit >= 300000 and oid_digit <= 309999:
        return (
            -1,
            "script_oid() in VT '"
            + str(file)
            + "' is using an invalid OID '"
            + str(oid)
            + "' (reserved OID range not part of the official Feed)",
        )

    return (
        -1,
        "script_oid() in VT '"
        + str(file)
        + "' is using an invalid OID '"
        + str(oid)
        + "' (unassigned OID range)",
    )


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = has_valid_oid(file)
            if test[0] == -1:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report("VTs using an incorrect OID syntax", error)
        sys.exit(1)

    sys.exit(0)

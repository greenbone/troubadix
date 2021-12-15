#!/usr/bin/env python3

from pathlib import Path
from typing import List
import re

ENCODING = "latin-1"


def has_valid_oid(nasl_file):
    """Checks if a NASL script is using a valid script_oid() tag.

    Valid:
    script_oid("1.3.6.1.4.1.25623.1.0.12345");
    script_oid('1.3.6.1.4.1.25623.1.0.12345');
    Any of the OID ranges mentioned in
    https://intra.greenbone.net/Production/GSF#All_ID_ranges

    Not valid:
    script_oid(""); (no OID included)
    script_oid(); (empty tag)
    script_oid("1.3.6.1.4.1.25623.1.12345"); (malformed)
    A OID range not mentioned in
    https://intra.greenbone.net/Production/GSF#All_ID_ranges

    Args:
        nasl_file: The VT that is going to be checked
    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message
    """

    content = nasl_file.read_text(encoding=ENCODING)
    oid_match = re.search(
        r'^\s*script_oid\s*\(\s*["\']([0-9.]+)["\']\s*\)\s*;',
        content,
        re.MULTILINE,
    )
    if oid_match is None or oid_match.group(1) is None:
        return (
            -1,
            f"No valid script_oid() call found in VT '{str(nasl_file.name)}'",
        )

    oid = oid_match.group(1)
    family_template = "Local Security Checks"
    is_using = "is using an OID that is reserved for"
    invalid_oid = "is using an invalid OID"

    if "1.3.6.1.4.1.25623.1." not in oid:
        return (
            -1,
            f"script_oid() in VT '{str(nasl_file.name)}' "
            f"{invalid_oid} "
            f"'{str(oid)}'",
        )

    # Vendor-specific OIDs
    if "1.3.6.1.4.1.25623.1.1" in oid:
        family_match = re.search(
            r'^\s*script_family\s*\(\s*["\']([0-9A-Za-z\s\-:\.]+)'
            r'["\']\s*\)\s*;',
            content,
            re.MULTILINE,
        )
        if family_match is None or family_match.group(1) is None:
            return (
                -1,
                f"VT '{str(nasl_file.name)}' is missing a script family!",
            )
        family = family_match.group(1)

        # Fixed OID-scheme for (Huawei) Euler OS OIDs
        if "1.3.6.1.4.1.25623.1.1.2." in oid:
            if family != f"Huawei EulerOS {family_template}":
                return (
                    -1,
                    f"VT '{str(nasl_file.name)}' {is_using} EulerOS VTs "
                    f""
                    f"'{str(oid)}'",
                )
            euler_sa_match = re.search(
                r"^1\.3\.6\.1\.4\.1\.25623\.1\.1\.2\.20[0-4][0-9]\.[0-9]{4}$",
                oid,
            )
            if euler_sa_match is None:
                return (
                    -1,
                    f"script_oid() in VT '{str(nasl_file.name)}' "
                    f"{invalid_oid} '{str(oid)}' (EulerOS pattern: "
                    "1.3.6.1.4.1.25623.1.1.2.[ADVISORY_YEAR].[ADVISORY_ID])",
                )
            return (0,)
        # Fixed OID-scheme for SUSE SLES OS OIDs
        elif "1.3.6.1.4.1.25623.1.1.4." in oid:
            if family != f"SuSE {family_template}":
                return (
                    -1,
                    f"VT '{str(nasl_file.name)}' {is_using} "
                    f"SUSE SLES VTs "
                    f"'{str(oid)}'",
                )
            sles_sa_match = re.search(
                r"^1\.3\.6\.1\.4\.1\.25623\.1\.1\.4\.20[0-4]"
                r"[0-9]\.[0-9]{4,5}\.[0-9]$",
                oid,
            )
            if sles_sa_match is None:
                return (
                    -1,
                    f"script_oid() in VT '{str(nasl_file.name)}' {invalid_oid}"
                    f" '{str(oid)}' (SLES pattern: 1.3.6.1.4.1.25623.1.1.4."
                    "[ADVISORY_YEAR].[ADVISORY_ID].[ADVISORY_REVISION])",
                )
            return (0,)
        else:
            vendor_number_match = re.search(
                r"^1\.3\.6\.1\.4\.1\.25623\.1\.1\.([0-9]+)\.", oid
            )
            if (
                vendor_number_match is None
                or vendor_number_match.group(1) is None
            ):
                return (
                    -1,
                    f"script_oid() in VT '{str(nasl_file.name)}' "
                    f"{invalid_oid} '{str(oid)}' (last digits)",
                )

            # link is too long.
            # https://gitlab.greenbone.net/tpassfeld/next-gen-lsc-poc/blob
            # /4b576e4af40614ac29d1dc8f341026fb5f39d5db/generator/config.cfg
            # #L9-21
            vendor_number = vendor_number_match.group(1)

            if vendor_number == "1":
                if family != f"Debian {family_template}":
                    return (
                        -1,
                        f"VT '{str(nasl_file.name)}' {is_using} Debian VTs "
                        f"'{str(oid)}'",
                    )

            elif vendor_number == "3":
                if family != f"CentOS {family_template}":
                    return (
                        -1,
                        f"VT '{str(nasl_file.name)}' {is_using} CentOS VTs "
                        f"'{str(oid)}'",
                    )

            elif vendor_number == "4":
                if family != f"CentOS {family_template}":
                    return (
                        -1,
                        f"VT '{str(nasl_file.name)}' {is_using} CentOS_CR VTs "
                        f"'{str(oid)}'",
                    )

            elif vendor_number == "5":
                if family != f"Fedora {family_template}":
                    return (
                        -1,
                        f"VT '{str(nasl_file.name)}' {is_using} Fedora VTs "
                        f"'{str(oid)}'",
                    )

            elif vendor_number == "6":
                if family != f"Gentoo {family_template}":
                    return (
                        -1,
                        f"VT '{str(nasl_file.name)}' {is_using} Gentoo VTs "
                        f"'{str(oid)}'",
                    )

            elif vendor_number == "7":
                if family != f"HP-UX {family_template}":
                    return (
                        -1,
                        f"VT '{str(nasl_file.name)}' {is_using} HP-UX VTs "
                        f"'{str(oid)}'",
                    )

            elif vendor_number == "8":
                if family != f"Mandrake {family_template}":
                    return (
                        -1,
                        f"VT '{str(nasl_file.name)}' {is_using} "
                        f"Mandrake/Mandriva VTs '{str(oid)}'",
                    )

            elif vendor_number == "9":
                if family != f"SuSE {family_template}":
                    return (
                        -1,
                        f"VT '{str(nasl_file.name)}' {is_using} openSUSE VTs "
                        f"'{str(oid)}'",
                    )

            elif vendor_number == "10":
                if family != f"Red Hat {family_template}":
                    return (
                        -1,
                        f"VT '{str(nasl_file.name)}' {is_using} Red Hat VTs "
                        f"'{str(oid)}'",
                    )

            elif vendor_number == "11":
                if family != f"Solaris {family_template}":
                    return (
                        -1,
                        f"VT '{str(nasl_file.name)}' {is_using} Solaris VTs "
                        f"'{str(oid)}'",
                    )

            elif vendor_number == "12":
                if family != f"SuSE {family_template}":
                    return (
                        -1,
                        f"VT '{str(nasl_file.name)}' {is_using} SUSE VTs "
                        f"'{str(oid)}'",
                    )

            elif vendor_number == "13":
                if family != f"Ubuntu {family_template}":
                    return (
                        -1,
                        f"VT '{str(nasl_file.name)}' {is_using} Ubuntu VTs "
                        f"'{str(oid)}'",
                    )
            else:
                return (
                    -1,
                    f"VT '{str(nasl_file.name)}' {invalid_oid} '{str(oid)}' "
                    "(Vendor OID with unknown Vendor-Prefix)",
                )

            return (0,)

    # product-specific OIDs
    if oid.startswith("1.3.6.1.4.1.25623.1.2."):
        name_match = re.search(
            r'^\s*script_name\s*\(\s*["\']([\w ()-]+)["\']\s*\)\s*;',
            content,
            re.MULTILINE,
        )
        if not name_match or not name_match.group(1):
            return -1, f"VT '{str(nasl_file.name)}' is missing a script name!"
        name = name_match.group(1)

        # Fixed OID-scheme for Mozilla Firefox OIDs
        if oid.startswith("1.3.6.1.4.1.25623.1.2.1."):
            if not name.startswith("Mozilla Firefox Security Advisory"):
                return (
                    -1,
                    f"VT '{str(nasl_file.name)}' {is_using} Firefox VTs "
                    f"'{str(oid)}'",
                )
            firefox_sa_match = re.search(
                r"^1\.3\.6\.1\.4\.1\.25623\.1\.2\.1"
                r"\.20[1-4][0-9]\.[0-9]{2,3}$",
                oid,
            )
            if not firefox_sa_match:
                return (
                    -1,
                    f"script_oid() in VT '{str(nasl_file.name)}' {invalid_oid}"
                    f" '{str(oid)}' (Firefox pattern: 1.3.6.1.4.1.25623.1.2.1."
                    "[ADVISORY_YEAR].[ADVISORY_ID])",
                )
            return (0,)

    oid_digit_match = re.search(
        r"^1\.3\.6\.1\.4\.1\.25623\.1\.0\.([0-9]+)", oid
    )
    if oid_digit_match is None or oid_digit_match.group(1) is None:
        return (
            -1,
            f"script_oid() in VT '{str(nasl_file.name)}' "
            f"{invalid_oid} '{str(oid)}' (last digits)",
        )

    # nb: Those are using invalid OID ranges but are already in
    # the feed since longer time and can't be fixed / changed.
    if (
        "ossim_server_detect.nasl" in nasl_file
        or (
            "gsf/2018/vmware/gb_vmware_fusion"
            "_vmxnet3_stack_memory_usage_vuln_macosx.nasl"
        )
        in nasl_file
        or "2008/asterisk_sdp_header_overflow.nasl" in nasl_file
        or "2008/cisco_ios_ftp_server_auth_bypass.nasl" in nasl_file
        or "2008/qk_smtp_server_dos.nasl" in nasl_file
        or "2008/asterisk_pbx_guest_access_enabled.nasl" in nasl_file
        or "2008/asterisk_null_pointer_dereference.nasl" in nasl_file
        or "2008/goaheadwebserver_source_disclosure.nasl" in nasl_file
        or "2011/secpod_ibm_lotus_domino_rpc_auth_dos_vuln.nasl" in nasl_file
        or "2011/secpod_cubecart_mult_xss_and_sql_inj_vuln.nasl" in nasl_file
        or "2016/gb_adobe_air_mult_vuln_feb16_macosx.nasl" in nasl_file
        or "attic/gb_cybozu_garoon_mult_vuln_aug16.nasl" in nasl_file
        or "2017/gb_openssh_mult_vuln_jan17_lin.nasl" in nasl_file
        or "2017/gb_xenserver_ctx219378.nasl" in nasl_file
    ):
        return (0,)

    oid_digit = int(oid_digit_match.group(1))

    # See https://confluence.greenbone.net/display/GSFDEV/OID+Assignment
    # for a list of valid/currently assigned OID ranges
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
            f"script_oid() in VT '{str(nasl_file.name)}' "
            f"{invalid_oid} '{str(oid)}' (reserved OID range "
            "not part of the official Feed)",
        )

    return (
        -1,
        f"script_oid() in VT '{str(nasl_file.name)}'  {invalid_oid} "
        f"'{str(oid)}' (unassigned OID range)",
    )


def check_nasl_files(nasl_files: List[Path]) -> None:
    for nasl_file in nasl_files:
        # Does only apply to NASL nasl_files.
        if nasl_file.suffix == ".nasl":
            has_valid_oid(nasl_file)


# if __name__ == "__main__":
#     import ci_helpers

#     error = []
#     nasl_files = ci_helpers.list_modified_nasl_files()
#     if nasl_files:
#         for nasl_file in nasl_files:
#             test = has_valid_oid(nasl_file)
#             if test[0] == -1:
#                 error.append(nasl_file)
#     else:
#         sys.exit(0)

#     if len(error) > 0:
#         ci_helpers.report("VTs using an incorrect OID syntax", error)
#         sys.exit(1)

#     sys.exit(0)

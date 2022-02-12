# Copyright (C) 2021 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

""" checking badwords in NASL scripts with the NASLinter """

from pathlib import Path
import re

from naslinter.plugin import LinterError, FileContentPlugin


class CheckValidOID(FileContentPlugin):
    name = "check_valid_oid"

    @staticmethod
    def run(nasl_file: Path, file_content: str):
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

        oid_match = re.search(
            r'^\s*script_oid\s*\(\s*["\']([0-9.]+)["\']\s*\)\s*;',
            file_content,
            re.MULTILINE,
        )
        if oid_match is None or oid_match.group(1) is None:
            yield LinterError(
                "No valid script_oid() call found" f" in VT '{nasl_file.name}'",
            )

        oid = oid_match.group(1)
        family_template = "Local Security Checks"
        is_using = "is using an OID that is reserved for"
        invalid_oid = "is using an invalid OID"

        if "1.3.6.1.4.1.25623.1." not in oid:
            yield LinterError(
                f"script_oid() in VT '{nasl_file.name}' "
                f"{invalid_oid} "
                f"'{str(oid)}'",
            )

        # Vendor-specific OIDs
        if "1.3.6.1.4.1.25623.1.1" in oid:
            family_match = re.search(
                r'^\s*script_family\s*\(\s*["\']([0-9A-Za-z\s\-:\.]+)'
                r'["\']\s*\)\s*;',
                file_content,
                re.MULTILINE,
            )
            if family_match is None or family_match.group(1) is None:
                yield LinterError(
                    f"VT '{nasl_file.name}' is missing a script family!"
                )
            family = family_match.group(1)

            # Fixed OID-scheme for (Huawei) Euler OS OIDs
            if "1.3.6.1.4.1.25623.1.1.2." in oid:
                if family != f"Huawei EulerOS {family_template}":
                    yield LinterError(
                        f"VT '{nasl_file.name}' {is_using} EulerOS VTs "
                        f"'{str(oid)}'",
                    )
                euler_sa_match = re.search(
                    r"^1\.3\.6\.1\.4\.1\.25623\."
                    r"1\.1\.2\.20[0-4][0-9]\.[0-9]{4}$",
                    oid,
                )
                if euler_sa_match is None:
                    yield LinterError(
                        f"script_oid() in VT '{nasl_file.name}' "
                        f"{invalid_oid} '{str(oid)}' (EulerOS pattern: "
                        "1.3.6.1.4.1.25623.1.1.2.[ADVISORY_YEAR]."
                        "[ADVISORY_ID])",
                    )
                return
            # Fixed OID-scheme for SUSE SLES OS OIDs
            elif "1.3.6.1.4.1.25623.1.1.4." in oid:
                if family != f"SuSE {family_template}":
                    yield LinterError(
                        f"VT '{nasl_file.name}' {is_using} "
                        f"SUSE SLES VTs "
                        f"'{str(oid)}'",
                    )
                sles_sa_match = re.search(
                    r"^1\.3\.6\.1\.4\.1\.25623\.1\.1\.4\.20[0-4]"
                    r"[0-9]\.[0-9]{4,5}\.[0-9]$",
                    oid,
                )
                if sles_sa_match is None:
                    yield LinterError(
                        f"script_oid() in VT '{nasl_file.name}' "
                        f"{invalid_oid} '{str(oid)}' (SLES pattern: 1.3.6.1.4."
                        "1.25623.1.1.4.[ADVISORY_YEAR].[ADVISORY_ID]."
                        "[ADVISORY_REVISION])",
                    )
                return
            else:
                vendor_number_match = re.search(
                    r"^1\.3\.6\.1\.4\.1\.25623\.1\.1\.([0-9]+)\.", oid
                )
                if (
                    vendor_number_match is None
                    or vendor_number_match.group(1) is None
                ):
                    yield LinterError(
                        f"script_oid() in VT '{nasl_file.name}' "
                        f"{invalid_oid} '{str(oid)}' (last digits)",
                    )

                # link is too long.
                # https://gitlab.greenbone.net/tpassfeld/next-gen-lsc-poc/blob
                # /4b576e4af40614ac29d1dc8f341026fb5f39d5db/generator/
                # config.cfg#L9-21
                vendor_number = vendor_number_match.group(1)

                if vendor_number == "1":
                    if family != f"Debian {family_template}":
                        return (
                            f"VT '{nasl_file.name}' {is_using} "
                            f" Debian VTs'{str(oid)}'",
                        )

                elif vendor_number == "3":
                    if family != f"CentOS {family_template}":
                        yield LinterError(
                            f"VT '{nasl_file.name}' {is_using} "
                            f"CentOS VTs '{str(oid)}'",
                        )

                elif vendor_number == "4":
                    if family != f"CentOS {family_template}":
                        yield LinterError(
                            f"VT '{nasl_file.name}' {is_using} "
                            f"CentOS_CR VTs '{str(oid)}'",
                        )

                elif vendor_number == "5":
                    if family != f"Fedora {family_template}":
                        yield LinterError(
                            f"VT '{nasl_file.name}' {is_using} "
                            f"Fedora VTs '{str(oid)}'",
                        )

                elif vendor_number == "6":
                    if family != f"Gentoo {family_template}":
                        yield LinterError(
                            f"VT '{nasl_file.name}' {is_using} "
                            f"Gentoo VTs '{str(oid)}'",
                        )

                elif vendor_number == "7":
                    if family != f"HP-UX {family_template}":
                        yield LinterError(
                            f"VT '{nasl_file.name}' {is_using} HP-UX VTs "
                            f"'{str(oid)}'",
                        )

                elif vendor_number == "8":
                    if family != f"Mandrake {family_template}":
                        yield LinterError(
                            f"VT '{nasl_file.name}' {is_using} "
                            f"Mandrake/Mandriva VTs '{str(oid)}'",
                        )

                elif vendor_number == "9":
                    if family != f"SuSE {family_template}":
                        yield LinterError(
                            f"VT '{nasl_file.name}' {is_using} "
                            f"openSUSE VTs '{str(oid)}'",
                        )

                elif vendor_number == "10":
                    if family != f"Red Hat {family_template}":
                        yield LinterError(
                            f"VT '{nasl_file.name}' {is_using} "
                            f"Red Hat VTs '{str(oid)}'",
                        )

                elif vendor_number == "11":
                    if family != f"Solaris {family_template}":
                        yield LinterError(
                            f"VT '{nasl_file.name}' {is_using} "
                            f"Solaris VTs '{str(oid)}'",
                        )

                elif vendor_number == "12":
                    if family != f"SuSE {family_template}":
                        yield LinterError(
                            f"VT '{nasl_file.name}' {is_using} SUSE VTs "
                            f"'{str(oid)}'",
                        )

                elif vendor_number == "13":
                    if family != f"Ubuntu {family_template}":
                        yield LinterError(
                            f"VT '{nasl_file.name}' {is_using} "
                            f"Ubuntu VTs '{str(oid)}'",
                        )
                else:
                    yield LinterError(
                        f"VT '{nasl_file.name}' {invalid_oid} "
                        "'{str(oid)}' (Vendor OID with unknown Vendor-Prefix)",
                    )

                return

        # product-specific OIDs
        if oid.startswith("1.3.6.1.4.1.25623.1.2."):
            name_match = re.search(
                r'^\s*script_name\s*\(\s*["\']([\w ()-]+)["\']\s*\)\s*;',
                file_content,
                re.MULTILINE,
            )
            if not name_match or not name_match.group(1):
                yield LinterError(
                    f"VT '{nasl_file.name}' is missing a script name!"
                )
            name = name_match.group(1)

            # Fixed OID-scheme for Mozilla Firefox OIDs
            if oid.startswith("1.3.6.1.4.1.25623.1.2.1."):
                if not name.startswith("Mozilla Firefox Security Advisory"):
                    yield LinterError(
                        f"VT '{nasl_file.name}' {is_using} Firefox VTs "
                        f"'{str(oid)}'",
                    )
                firefox_sa_match = re.search(
                    r"^1\.3\.6\.1\.4\.1\.25623\.1\.2\.1"
                    r"\.20[1-4][0-9]\.[0-9]{2,3}$",
                    oid,
                )
                if not firefox_sa_match:
                    yield LinterError(
                        f"script_oid() in VT '{nasl_file.name}' "
                        f"{invalid_oid} '{str(oid)}' (Firefox pattern: 1."
                        "3.6.1.4.1.25623.1.2.1.[ADVISORY_YEAR].[ADVISORY_ID])",
                    )
                return

        oid_digit_match = re.search(
            r"^1\.3\.6\.1\.4\.1\.25623\.1\.0\.([0-9]+)", oid
        )
        if oid_digit_match is None or oid_digit_match.group(1) is None:
            yield LinterError(
                f"script_oid() in VT '{nasl_file.name}' "
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
            or "2011/secpod_ibm_lotus_domino_rpc_auth_dos_vuln.nasl"
            in nasl_file
            or "2011/secpod_cubecart_mult_xss_and_sql_inj_vuln.nasl"
            in nasl_file
            or "2016/gb_adobe_air_mult_vuln_feb16_macosx.nasl" in nasl_file
            or "attic/gb_cybozu_garoon_mult_vuln_aug16.nasl" in nasl_file
            or "2017/gb_openssh_mult_vuln_jan17_lin.nasl" in nasl_file
            or "2017/gb_xenserver_ctx219378.nasl" in nasl_file
        ):
            return

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
            return

        if oid_digit >= 300000 and oid_digit <= 309999:
            yield LinterError(
                f"script_oid() in VT '{nasl_file.name}' "
                f"{invalid_oid} '{str(oid)}' (reserved OID range "
                "not part of the official Feed)",
            )

        yield LinterError(
            f"script_oid() in VT '{nasl_file.name}'  {invalid_oid} "
            f"'{str(oid)}' (unassigned OID range)",
        )

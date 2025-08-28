# Copyright (C) 2021 Greenbone AG
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

import re
from pathlib import Path
from typing import Iterator

from troubadix.helper.patterns import (
    SpecialScriptTag,
    get_special_script_tag_pattern,
)
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class CheckValidOID(FileContentPlugin):
    name = "check_valid_oid"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """Checks if a NASL script is using a valid script_oid() tag.

        Valid:
        script_oid("1.3.6.1.4.1.25623.1.0.12345");
        script_oid('1.3.6.1.4.1.25623.1.0.12345');

        Not valid:
        script_oid(""); (no OID included)
        script_oid(); (empty tag)
        script_oid("1.3.6.1.4.1.25623.1.12345"); (malformed)

        Args:
            nasl_file: The VT that is going to be checked
            file_content: The content of the nasl_file

        """
        if (
            nasl_file.suffix == ".inc"
            or "# troubadix: disable=template_nd_test_files_fps" in file_content
        ):
            return

        security_template = "Security Advisory"
        family_template = "Local Security Checks"
        is_using_reserved = "is using an OID that is reserved for"
        invalid_oid = "is using an invalid OID"

        oid_pattern = get_special_script_tag_pattern(SpecialScriptTag.OID)
        oid_match = oid_pattern.search(file_content)
        if oid_match is None or oid_match.group("oid") is None:
            yield LinterError(
                "No valid script_oid() call found",
                file=nasl_file,
                plugin=self.name,
            )
            return

        oid = oid_match.group("oid")

        if "1.3.6.1.4.1.25623.1." not in oid:
            yield LinterError(
                f"script_oid() {invalid_oid} '{str(oid)}'",
                file=nasl_file,
                plugin=self.name,
            )
            return

        family_pattern = get_special_script_tag_pattern(SpecialScriptTag.FAMILY)
        family_match = family_pattern.search(file_content)

        if family_match is None or family_match.group("value") is None:
            yield LinterError(
                "VT is missing a script family!",
                file=nasl_file,
                plugin=self.name,
            )
            return

        # Vendor-specific OIDs
        if "1.3.6.1.4.1.25623.1.1." in oid:
            family = family_match.group("value")
            vendor_number_match = re.search(
                r"^1\.3\.6\.1\.4\.1\.25623\.1\.1\.([0-9]+)\.", oid
            )
            if (
                vendor_number_match is None
                or vendor_number_match.group(1) is None
            ):
                yield LinterError(
                    f"script_oid() {invalid_oid} '{str(oid)}' (last digits)",
                    file=nasl_file,
                    plugin=self.name,
                )
                return

            vendor_number = vendor_number_match.group(1)

            if vendor_number == "1":
                if family != f"Debian {family_template}":
                    yield LinterError(
                        f"script_oid() {is_using_reserved} Debian "
                        f"'{str(oid)}'",
                        file=nasl_file,
                        plugin=self.name,
                    )
                    return

            elif vendor_number == "2":
                if family != f"Huawei EulerOS {family_template}":
                    yield LinterError(
                        f"script_oid() {is_using_reserved} EulerOS "
                        f"'{str(oid)}'",
                        file=nasl_file,
                        plugin=self.name,
                    )
                    return

                # Fixed OID-scheme for (Huawei) Euler OS OIDs
                euler_sa_match = re.search(
                    r"^1\.3\.6\.1\.4\.1\.25623\.1\.1\.2\.20[0-4][0-9]\.[0-9]{"
                    r"4}$",
                    oid,
                )
                if euler_sa_match is None:
                    yield LinterError(
                        f"script_oid() {invalid_oid} '{str(oid)}' (EulerOS "
                        "pattern: 1.3.6.1.4.1.25623.1.1.2.[ADVISORY_YEAR]"
                        ".[ADVISORY_ID])",
                        file=nasl_file,
                        plugin=self.name,
                    )
                return

            elif vendor_number == "4":
                if family != f"SuSE {family_template}":
                    yield LinterError(
                        f"script_oid() {is_using_reserved} SUSE SLES "
                        f"'{str(oid)}'",
                        file=nasl_file,
                        plugin=self.name,
                    )
                    return

                # Fixed OID-scheme for SUSE SLES OS OIDs
                sles_sa_match = re.search(
                    r"^1\.3\.6\.1\.4\.1\.25623\.1\.1\.4\.20[0-4][0-9]\.[0-9]{"
                    r"4,5}\.[0-9]$",
                    oid,
                )
                if sles_sa_match is None:
                    yield LinterError(
                        f"script_oid() {invalid_oid} '{str(oid)}' (SLES "
                        f"pattern: 1.3.6.1.4.1.25623.1.1.4.[ADVISORY_YEAR]"
                        f".[ADVISORY_ID].[ADVISORY_REVISION])",
                        file=nasl_file,
                        plugin=self.name,
                    )
                return

            elif vendor_number == "5":
                if family != f"Amazon Linux {family_template}":
                    yield LinterError(
                        f"script_oid() {is_using_reserved} Amazon Linux "
                        f"'{str(oid)}'",
                        file=nasl_file,
                        plugin=self.name,
                    )
                    return

                amazon_sa_match = re.search(
                    r"^1\.3\.6\.1\.4\.1\.25623\.1\.1\.5\.([1-3]\.)?20[0-4][0-9]\.[0-9]+$",
                    oid,
                )
                if amazon_sa_match is None:
                    yield LinterError(
                        f"script_oid() {invalid_oid} '{str(oid)}' (Amazon "
                        "pattern: 1.3.6.1.4.1.25623.1.1.5.[OPTIONAL PRODUCT PREFIX.][ADVISORY_YEAR]"
                        ".[ADVISORY_ID])",
                        file=nasl_file,
                        plugin=self.name,
                    )
                return

            elif vendor_number == "6":
                if family != f"Gentoo {family_template}":
                    yield LinterError(
                        f"script_oid() {is_using_reserved} Gentoo "
                        f"'{str(oid)}'",
                        file=nasl_file,
                        plugin=self.name,
                    )
                    return

            elif vendor_number == "7":
                if family != "FreeBSD Local Security Checks":
                    yield LinterError(
                        f"script_oid() {is_using_reserved} FreeBSD "
                        f"'{str(oid)}'",
                        file=nasl_file,
                        plugin=self.name,
                    )
                    return

            elif vendor_number == "8":
                if family != f"Oracle Linux {family_template}":
                    yield LinterError(
                        f"script_oid() {is_using_reserved} Oracle Linux "
                        f"'{str(oid)}'",
                        file=nasl_file,
                        plugin=self.name,
                    )
                    return

            elif vendor_number == "9":
                if family != f"Fedora {family_template}":
                    yield LinterError(
                        f"script_oid() {is_using_reserved} Fedora "
                        f"'{str(oid)}'",
                        file=nasl_file,
                        plugin=self.name,
                    )
                    return

            elif vendor_number == "10":
                if family != f"Mageia Linux {family_template}":
                    yield LinterError(
                        f"script_oid() {is_using_reserved} Mageia Linux "
                        f"'{str(oid)}'",
                        file=nasl_file,
                        plugin=self.name,
                    )
                    return

                mageia_sa_match = re.search(
                    r"^1\.3\.6\.1\.4\.1\.25623\.1\.1\.10\.20[0-4][0-9]\.["
                    r"0-9]{4}$",
                    oid,
                )
                if mageia_sa_match is None:
                    yield LinterError(
                        f"script_oid() {invalid_oid} '{str(oid)}' (Mageia "
                        "pattern: 1.3.6.1.4.1.25623.1.1.10.[ADVISORY_YEAR]"
                        ".[ADVISORY_ID])",
                        file=nasl_file,
                        plugin=self.name,
                    )
                return

            elif vendor_number == "11":
                if family != f"Red Hat {family_template}":
                    yield LinterError(
                        f"script_oid() {is_using_reserved} Red Hat "
                        f"'{str(oid)}'",
                        file=nasl_file,
                        plugin=self.name,
                    )
                    return

            elif vendor_number == "12":
                if family != f"Ubuntu {family_template}":
                    yield LinterError(
                        f"script_oid() {is_using_reserved} Ubuntu "
                        f"'{str(oid)}'",
                        file=nasl_file,
                        plugin=self.name,
                    )
                    return

            elif vendor_number == "13":
                if family != f"Slackware {family_template}":
                    yield LinterError(
                        f"script_oid() {is_using_reserved} Slackware "
                        f"'{str(oid)}'"
                    )
                    return

                slackware_sa_match = re.search(
                    r"^1\.3\.6\.1\.4\.1\.25623\.1\.1\.13\.20[0-4][0-9]\.[0-9]"
                    r"{3,4}\.[0-9]{2}$",
                    oid,
                )
                if slackware_sa_match is None:
                    yield LinterError(
                        f"script_oid() {invalid_oid} '{str(oid)}' (Slackware "
                        "pattern: 1.3.6.1.4.1.25623.1.1.13.[ADVISORY_YEAR]"
                        ".[ADVISORY_ID].[ADVISORY_REVISION])"
                    )
                return

            elif vendor_number == "14":
                if family != f"Rocky Linux {family_template}":
                    yield LinterError(
                        f"script_oid() {is_using_reserved} Rocky Linux "
                        f"'{str(oid)}'",
                        file=nasl_file,
                        plugin=self.name,
                    )
                    return

            elif vendor_number == "15":
                if family != f"AlmaLinux {family_template}":
                    yield LinterError(
                        f"script_oid() {is_using_reserved} AlmaLinux "
                        f"'{str(oid)}'",
                        file=nasl_file,
                        plugin=self.name,
                    )
                    return
            elif vendor_number == "18":
                if family != f"openSUSE {family_template}":
                    yield LinterError(
                        f"script_oid() {is_using_reserved} openSUSE "
                        f"'{str(oid)}'",
                        file=nasl_file,
                        plugin=self.name,
                    )
                    return

            else:
                yield LinterError(
                    f"script_oid() {invalid_oid} '{str(oid)}' (Vendor OID "
                    "with unknown Vendor-Prefix)",
                    file=nasl_file,
                    plugin=self.name,
                )
                return

            return

        # product-specific OIDs
        if "1.3.6.1.4.1.25623.1.2." in oid:
            name_pattern = get_special_script_tag_pattern(SpecialScriptTag.NAME)
            name_match = name_pattern.search(file_content)
            if not name_match or not name_match.group("value"):
                yield LinterError(
                    "VT is missing a script name!",
                    file=nasl_file,
                    plugin=self.name,
                )
                return

            name = name_match.group("value")

            # Fixed OID-scheme for Mozilla Firefox OIDs
            if "1.3.6.1.4.1.25623.1.2.1." in oid:
                if not name.startswith(f"Mozilla Firefox {security_template}"):
                    yield LinterError(
                        f"script_oid() {is_using_reserved} 'Firefox' ("
                        f"{str(oid)})",
                        file=nasl_file,
                        plugin=self.name,
                    )
                    return

                firefox_sa_match = re.search(
                    r"^1\.3\.6\.1\.4\.1\.25623\.1\.2\.1\.20[1-4][0-9]\.[0-9]{"
                    r"2,3}$",
                    oid,
                )
                if not firefox_sa_match:
                    yield LinterError(
                        f"script_oid() {invalid_oid} '{str(oid)}' "
                        "(Firefox pattern: 1.3.6.1.4.1.25623.1.2.1."
                        "[ADVISORY_YEAR].[ADVISORY_ID])",
                        file=nasl_file,
                        plugin=self.name,
                    )
                    return

                return

        # Fixed OID-scheme for Windows OIDs
        if "1.3.6.1.4.1.25623.1.3." in oid:
            if family_match.group("value") != f"Windows {family_template}":
                yield LinterError(
                    f"script_oid() {is_using_reserved} 'Windows' ("
                    f"{str(oid)})",
                    file=nasl_file,
                    plugin=self.name,
                )
                return

            windows_oid_match = re.search(
                r"^1\.3\.6\.1\.4\.1\.25623\.1\.3\.\d+\.\d+\.\d+\.\d+",
                oid,
            )
            if not windows_oid_match:
                yield LinterError(
                    f"script_oid() {invalid_oid} '{str(oid)}' "
                    "(Windows pattern: 1.3.6.1.4.1.25623.1.3."
                    "[product_id].[platform_id].[kb_article_id].[fixed_build_number])",
                    file=nasl_file,
                    plugin=self.name,
                )
                return
            return

        oid_digit_match = re.search(
            r"^1\.3\.6\.1\.4\.1\.25623\.1\.0\.([0-9]+)", oid
        )
        if oid_digit_match is None or oid_digit_match.group(1) is None:
            yield LinterError(
                f"script_oid() {invalid_oid} '{str(oid)}' (last digits)",
                file=nasl_file,
                plugin=self.name,
            )
            return

        exceptions = [
            "ossim_server_detect.nasl",
            "gsf/2018/vmware/gb_vmware_fusion_vmxnet3_"
            + "stack_memory_usage_vuln_macosx.nasl",
            "2008/asterisk_sdp_header_overflow.nasl",
            "2008/cisco_ios_ftp_server_auth_bypass.nasl",
            "2008/qk_smtp_server_dos.nasl",
            "2008/asterisk_pbx_guest_access_enabled.nasl",
            "2008/asterisk_null_pointer_dereference.nasl",
            "2008/goaheadwebserver_source_disclosure.nasl",
            "2011/gb_ibm_lotus_domino_rpc_auth_dos_vuln.nasl",
            "2011/gb_cubecart_mult_xss_and_sql_inj_vuln.nasl",
            "2016/gb_adobe_air_mult_vuln_feb16_macosx.nasl",
            "attic/gb_cybozu_garoon_mult_vuln_aug16.nasl",
            "2017/gb_openssh_mult_vuln_jan17_lin.nasl",
            "2017/gb_xenserver_ctx219378.nasl",
        ]
        # nb: Those are using invalid OID ranges but are already in
        # the feed since longer time and can't be fixed / changed.
        if any(e in str(nasl_file) for e in exceptions):
            return

        oid_digit = int(oid_digit_match.group(1))

        if (
            (10000 <= oid_digit <= 29999)
            or (50000 <= oid_digit <= 179999)
            or (200000 <= oid_digit <= 209999)
            or (700000 <= oid_digit <= 919999)
            or (1020000 <= oid_digit <= 1029999)
        ):
            return

        if 300000 <= oid_digit <= 309999:
            yield LinterError(
                f"script_oid() {invalid_oid} '{str(oid)}' (reserved OID "
                "range not part of the official Feed)",
                file=nasl_file,
                plugin=self.name,
            )
            return

        yield LinterError(
            f"script_oid() {invalid_oid} "
            f"'{str(oid)}' (unassigned OID range)",
            file=nasl_file,
            plugin=self.name,
        )

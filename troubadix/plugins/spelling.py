#  Copyright (c) 2022 Greenbone Networks GmbH
#
#  SPDX-License-Identifier: GPL-3.0-or-later
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

import io
import re
from contextlib import redirect_stdout
from pathlib import Path
from typing import Iterator

from codespell_lib import main as codespell_main

from troubadix.plugin import FilesPlugin, LinterError, LinterResult

plugin_path = Path(__file__).parent.resolve()
codespell_config_path = (plugin_path.parent / "codespell").resolve()


class CheckSpelling(FilesPlugin):
    name = "check_spelling"

    def run(self) -> Iterator[LinterResult]:
        """This script checks, via the codespell library, wether
        the provided nasl files contain spelling errors.
        Certain errors are ignored based on listed exceptions

        Yields:
            Iterator[LinterResult]: The detected spelling errors
        """

        # Overwrite with local repository files if exist
        if Path("codespell.additions").exists():
            codespell_additions = Path("codespell.additions").resolve()
        else:
            codespell_additions = f"{codespell_config_path}/codespell.additions"
        if Path("codespell.exclude").exists():
            codespell_exclude = Path("codespell.exclude").resolve()
        else:
            codespell_exclude = f"{codespell_config_path}/codespell.exclude"
        if Path("codespell.ignore").exists():
            codespell_ignore = Path("codespell.ignore").resolve()
        else:
            codespell_ignore = f"{codespell_config_path}/codespell.ignore"

        batch_size = 10_000
        for i in range(0, len(self.context.nasl_files), batch_size):

            files_parameters = [
                str(nasl_file)
                for nasl_file in self.context.nasl_files[i : i + batch_size]
            ]
            codespell_arguments = [
                "--hard-encoding-detection",
                "--dictionary=-",
                f"--dictionary={codespell_additions}",
                f"--exclude-file={codespell_exclude}",
                f"--ignore-words={codespell_ignore}",
                "--disable-colors",
            ] + files_parameters

            with redirect_stdout(io.StringIO()) as codespell:
                codespell_main(*codespell_arguments)

            codespell = codespell.getvalue()
            if "Traceback (most recent call last):" not in codespell:
                _codespell = codespell.splitlines()
                codespell = ""
                for line in _codespell:

                    # From /Policy which is just a huge blob of text
                    # and too large for codespell.exclude:
                    if "policy_file_checksums_win.nasl" in line:
                        if re.search(r"nD\s+==>\s+and, 2nd", line) or re.search(
                            r"oD\s+==>\s+of", line
                        ):
                            continue

                    # Same for a few other files:
                    if "smtp_AV_42zip_DoS.nasl" in line and re.search(
                        r"BA\s+==>\s+BY, BE", line
                    ):
                        continue

                    if "bad_ssh_host_keys.inc" in line and re.search(
                        r"ba\s+==>\s+by, be", line
                    ):
                        continue

                    if "wmi_misc.inc" in line:
                        if re.search(r"BA\s+==>\s+BY, BE", line) or re.search(
                            r"OD\s+==>\s+OF", line
                        ):
                            continue

                    if (
                        "ssl_funcs.inc" in line
                        or "gb_ssl_tls_cert_details.nasl" in line
                    ):
                        if re.search(r"fpr\s+==>\s+for, far, fps", line):
                            continue

                    # Codespell has currently cna->can in the dictionary.txt
                    # which is causing false positives for CNA (widely used term
                    # in VTs) because codespell doesn't look at the casing. For
                    # now we're excluding any uppercase "CNA" results because
                    # these are usually false positives we don't want to report.
                    # Similar with "RO" because that is also very likely a false
                    # positive.
                    if re.search(r"CNA\s+==>\s+CAN", line) or re.search(
                        r"RO\s+==>\s+TO", line
                    ):
                        continue

                    # Name of a Huawei product
                    if (
                        "gb_huawei" in line
                        or "telnetserver_detect_type_nd_version.nasl" in line
                    ):
                        if re.search(
                            r"eSpace\s+==>\s+escape", line, flags=re.IGNORECASE
                        ):
                            continue

                    # "ure" is a Debian package, again too many hits for
                    # codespell.exclude.
                    if re.search(
                        r"(deb_(dla_)?[0-9]+(_[" r"0-9]+)?|gb_ubuntu_.+)\.nasl",
                        line,
                    ):
                        if re.search(r"ure\s+==>\s+sure", line):
                            continue

                    # gsf/PCIDSS VTs are currently using some german text parts
                    # nb: codespell seems to have some issues with
                    # german umlauts in the codespell.exclude so a few of these
                    # were also excluded here instead of directly
                    # via codespell.exclude.
                    if (
                        "PCIDSS/" in line
                        or "GSHB/" in line
                        or "attic/PCIDSS_" in line
                        or "ITG_Kompendium/" in line
                    ):
                        if re.search(
                            r"(sie|ist|oder|prozess|manuell|unter|funktion|"
                            r"alle|als|tage|lokale|uptodate|paket|titel|ba|"
                            r"ordner|modul|interaktive|programm|explizit|"
                            r"normale|applikation|attributen|lokal|signatur|"
                            r"modell|klick|generell)\s+==>\s+",
                            line,
                            flags=re.IGNORECASE,
                        ):
                            continue

                    # False positives in the gsf/PCIDSS and GSHB/ VTs:
                    # string('\nIn the file sent\nin milliseconds
                    # There are too many hits to maintain
                    # them in codespell.exclude so exclude them for now here.
                    if (
                        "PCIDSS/" in line
                        or "GSHB/" in line
                        or "attic/PCIDSS_" in line
                    ):
                        if re.search(r"n[iI]n\s+==>\s+inn", line):
                            continue

                    # False positives in the GSHB/ and ITG_Kompendium/ VTs on
                    # bsi.bund.de URLs.
                    if (
                        "GSHB/" in line
                        or "ITG_Kompendium/" in line
                        or "Policy/gb_policy_cipher_suites.nasl" in line
                        or "Policy/policy_BSI-TR-03116-4.nasl" in line
                        or "2012/gb_secpod_ssl_ciphers_weak_report.nasl" in line
                    ):
                        if re.search(r"bund\s+==>\s+bind", line):
                            continue

                    # False positive in this VT in German example responses.
                    if "gb_exchange_server_CVE-2021-26855_active.nasl" in line:
                        if re.search(r"ist\s+==>\s+is", line):
                            continue

                    # Mostly a false positive in LSCs because of things like
                    # "ALSA: hda" or a codec called "Conexant". There are too
                    # many hits to maintain them in codespell.exclude so exclude
                    # them for now here.
                    if re.search(
                        r"gb_(sles|(open)?suse|ubuntu_USN)_.+\.nasl", line
                    ):
                        if re.search(
                            r"(hda|conexant)\s+==>\s+(had|connexant)",
                            line,
                            flags=re.IGNORECASE,
                        ):
                            continue

                    # Jodie Chancel is a security researcher who is mentioned
                    # many times in Mozilla advisories
                    if re.search(
                        r"gb_mozilla_firefox_mfsa_\d{4}-\d{2,4}_lin\.nasl", line
                    ) and re.search(r"Chancel\s+==>\s+Cancel", line):
                        continue

                    # Look like correct as this is also in dictionary_rare.txt
                    if "deb_dla_2896.nasl" in line and re.search(
                        r"dependant\s+==>\s+dependent", line
                    ):
                        continue

                    # Similar to the one above for e.g. SLES.
                    # Also exclude "tre", because it's a package name.
                    if re.search(r"mgasa-\d{4}-\d{4}.nasl", line) and re.search(
                        r"(hda|tre|conexant)\s+==>\s+(had|tree|connexant)",
                        line,
                        flags=re.IGNORECASE,
                    ):
                        continue

                    # Similar to the corrections above, with some additional
                    # exclusions like e.g. names
                    if re.search(r"ELSA-\d{4}-\d{4,5}\.nasl", line):
                        if (
                            re.search(r"Stange\s+==>\s+Strange", line)
                            or re.search(r"chang\s+==>\s+change, charge", line)
                            or re.search(
                                r"IST\s+==>\s+IS, IT, ITS, IT'S, SIT, LIST",
                                line,
                            )
                            or re.search(r"hda\s+==>\s+had", line)
                            or re.search(r"Readded\s+==>\s+Read", line)
                            or re.search(
                                r"ACI\s+==>\s+ACPI", line, re.IGNORECASE
                            )
                            or re.search(r"UE\s+==>\s+USE, DUE", line)
                        ):
                            continue

                    # "Unsecure" is used in the references so we shouldn't
                    # change that.
                    if (
                        "office2013_allow_insecure_apps_catalogs.nasl" in line
                        or "gb_sap_rfc_default_pw.nasl" in line
                        or "gb_sap_webgui_default_pw.nasl" in line
                    ):
                        if re.search(r"[Uu]nsecure\s+==>\s+[Ii]nsecure", line):
                            continue

                    codespell += line + "\n"

            for codespell_entry in codespell.splitlines():
                if "==>" in codespell:
                    yield LinterError(
                        codespell_entry,
                        file=codespell_entry.split(":")[0],
                        plugin=self.name,
                    )
                elif "Traceback (most recent call last):" in codespell:
                    yield LinterError(
                        codespell,
                        plugin=self.name,
                    )

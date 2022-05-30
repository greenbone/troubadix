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
import re
from pathlib import Path
from typing import Iterator

from troubadix.helper.helper import subprocess_cmd, which
from troubadix.plugin import (
    FilePlugin,
    LinterError,
    LinterResult,
)

PluginPath = Path(__file__).parent.resolve()
CodespellConfigPath = (PluginPath.parent / "codespell").resolve()


class CheckSpelling(FilePlugin):
    name = "check_spelling"

    def run(self) -> Iterator[LinterResult]:
        """'codespell' is required to execute this step!
        This script opens a shell in a subprocess and executes 'codespell' to
        check the VT for spelling mistakes. An error will be thrown if
        'codespell' is not installed or corrections could be found via
        'codespell'.

        Args:
            nasl_file: The VT that is going to be checked
            _file_content: The content of the VT

        """
        codespell = ""
        program = which("codespell")
        if program is None:
            yield LinterError(
                "codespell tool not found within your PATH. Please install it "
                "via e.g. 'pip3 install codespell' or 'apt-get install "
                "codespell' and make sure it is available within your PATH.",
                file=self.context.nasl_file,
                plugin=self.name,
            )
            return

        out, err = subprocess_cmd(
            "codespell --hard-encoding-detection --dictionary=- "
            f"--dictionary={CodespellConfigPath}/codespell.additions "
            f"--exclude-file={CodespellConfigPath}/codespell.exclude "
            f"--ignore-words={CodespellConfigPath}/codespell.ignore "
            f"--disable-colors {str(self.context.nasl_file)}",
        )
        codespell = (out + "\n" + err).strip("\n")

        if (
            codespell is not None
            and "Traceback (most recent call last):" not in codespell
        ):
            _codespell = codespell.splitlines()
            codespell = ""
            for line in _codespell:

                # From /Policy which is just a huge blob of text and too large
                # for codespell.exclude:
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
                # nb: codespell seems to have some issues with german umlauts
                # in the codespell.exclude so a few of these were also excluded
                # here instead of directly via codespell.exclude.
                if (
                    "PCIDSS/" in line
                    or "GSHB/" in line
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
                # There are too many hits to maintain them in codespell.exclude
                # so exclude them for now here.
                if "PCIDSS/" in line or "GSHB/" in line:
                    if re.search(r"n[iI]n\s+==>\s+inn", line):
                        continue

                # False positive in this VT in German example responses.
                if "gb_exchange_server_CVE-2021-26855_active.nasl" in line:
                    if re.search(r"ist\s+==>\s+is", line):
                        continue

                # Mostly a false positive in LSCs because of things like
                # "ALSA: hda" or a codec called "Conexant". There are too
                # many hits to maintain them in codespell.exclude so exclude
                # them for now here.
                if re.search(r"gb_(sles|(open)?suse)_.+\.nasl", line):
                    if re.search(
                        r"(hda|conexant)\s+==>\s+(had|connexant)",
                        line,
                        flags=re.IGNORECASE,
                    ):
                        continue

                # Jodie Chancel is a security researcher who is mentioned many
                # times in Mozilla advisories
                if re.search(
                    r"gb_mozilla_firefox_mfsa_\d{4}-\d{2,4}_lin\.nasl", line
                ) and re.search(r"Chancel\s+==>\s+Cancel", line):
                    continue

                # Look like correct as this is also in dictionary_rare.txt
                if "deb_dla_2896.nasl" in line and re.search(
                    r"dependant\s+==>\s+dependent", line
                ):
                    continue

                # Similar to the one above for SLES: "ALSA: hda". Also exclude
                # "tre", because it's a package name
                if re.search(r"mgasa-\d{4}-\d{4}.nasl", line) and re.search(
                    r"(hda|tre)\s+==>\s+(had|tree)", line, flags=re.IGNORECASE
                ):
                    continue

                # Similar to the corrections above, with some additional
                # exclusions like e.g. names
                if re.search(r"ELSA-\d{4}-\d{4,5}\.nasl", line):
                    if (
                        re.search(r"Stange\s+==>\s+Strange", line)
                        or re.search(r"chang\s+==>\s+change, charge", line)
                        or re.search(
                            r"IST\s+==>\s+IS, IT, ITS, IT'S, SIT, LIST", line
                        )
                        or re.search(r"hda\s+==>\s+had", line)
                        or re.search(r"Readded\s+==>\s+Read", line)
                        or re.search(r"ACI\s+==>\s+ACPI", line, re.IGNORECASE)
                        or re.search(r"UE\s+==>\s+USE, DUE", line)
                    ):
                        continue

                codespell += line + "\n"

        if codespell and "==>" in codespell:
            yield LinterError(
                codespell,
                file=self.context.nasl_file,
                plugin=self.name,
            )
        elif codespell and "Traceback (most recent call last):" in codespell:
            yield LinterError(
                codespell,
                file=self.context.nasl_file,
                plugin=self.name,
            )

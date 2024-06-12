#  Copyright (c) 2022 Greenbone AG
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
from typing import Iterator, Tuple

from codespell_lib import main as codespell_main

from troubadix.helper.linguistic_exception_handler import (
    PatternInFileCheck,
    PatternInFilePatternCheck,
    PatternInFilesCheck,
    PatternsCheck,
    PatternsInFileCheck,
    PatternsInFilePatternCheck,
    handle_linguistic_checks,
)
from troubadix.plugin import FilesPlugin, LinterError, LinterResult

plugin_path = Path(__file__).parent.resolve()
codespell_config_path = (plugin_path.parent / "codespell").resolve()


exceptions = [
    # From /Policy which is just a huge blob of text
    # and too large for codespell.exclude:
    PatternsInFileCheck(
        "policy_file_checksums_win.nasl",
        [r"nD\s+==>\s+and, 2nd", r"oD\s+==>\s+of"],
    ),
    # Same for a few other files:
    PatternInFileCheck("smtp_AV_42zip_DoS.nasl", r"BA\s+==>\s+BY, BE"),
    PatternInFileCheck("bad_ssh_host_keys.inc", r"ba\s+==>\s+by, be"),
    PatternsInFileCheck(
        "wmi_misc.inc", [r"BA\s+==>\s+BY, BE", r"OD\s+==>\s+OF"]
    ),
    PatternInFilesCheck(
        ["ssl_funcs.inc", "gb_ssl_tls_cert_details.nasl"],
        r"fpr\s+==>\s+for, far, fps",
    ),
    # Codespell has currently cna->can in the dictionary.txt
    # which is causing false positives for CNA (widely used term
    # in VTs) because codespell doesn't look at the casing. For
    # now we're excluding any uppercase "CNA" results because
    # these are usually false positives we don't want to report.
    # Similar with "RO" because that is also very likely a false
    # positive.
    PatternsCheck([r"CNA\s+==>\s+CAN", r"RO\s+==>\s+TO"]),
    # Name of a Huawei product
    PatternInFilesCheck(
        ["gb_huawei", "telnetserver_detect_type_nd_version.nasl"],
        r"eSpace\s+==>\s+escape",
        re.IGNORECASE,
    ),
    # "ure" is a Debian package, again too many hits for
    # codespell.exclude.
    PatternInFilePatternCheck(
        r"(deb_(dla_)?[0-9]+(_[0-9]+)?|gb_ubuntu_.+)\.nasl",
        r"ure\s+==>\s+sure",
    ),
    # gsf/attic/PCIDSS*/ VTs are currently using some german text parts
    # nb: codespell seems to have some issues with
    # german umlauts in the codespell.exclude so a few of these
    # were also excluded here instead of directly
    # via codespell.exclude.
    PatternInFilesCheck(
        [
            "attic/PCIDSS/",
            "GSHB/",
            "attic/PCIDSS-2.0/",
            "ITG_Kompendium/",
            "Policy/ITG/",
        ],
        r"(sie|ist|oder|prozess|manuell|unter|funktion|"
        r"alle|als|tage|lokale|uptodate|paket|titel|ba|"
        r"ordner|modul|interaktive|programm|explizit|"
        r"normale|applikation|attributen|lokal|signatur|"
        r"modell|klick|generell|vor)\s+==>\s+",
        re.IGNORECASE,
    ),
    # False positives in the gsf/attic/PCIDSS*/ and GSHB/ VTs:
    # string('\nIn the file sent\nin milliseconds
    # There are too many hits to maintain
    # them in codespell.exclude so exclude them for now here.
    PatternInFilesCheck(
        ["attic/PCIDSS/", "GSHB/", "attic/PCIDSS-2.0/", "Policy/ITG/"],
        r"n[iI]n\s+==>\s+inn",
    ),
    # False positive in this VT in German example responses.
    PatternInFileCheck(
        "gb_exchange_server_CVE-2021-26855_active.nasl", r"ist\s+==>\s+is"
    ),
    # Mostly a false positive in LSCs because of things like
    # "ALSA: hda" or a codec called "Conexant". There are too
    # many hits to maintain them in codespell.exclude so exclude
    # them for now here.
    PatternInFilePatternCheck(
        r"gb_(sles|(open)?suse|ubuntu_USN)_.+\.nasl",
        r"(hda|conexant)\s+==>\s+(had|connexant)",
        text_pattern_flags=re.IGNORECASE,
    ),
    # Jodie Chancel is a security researcher who is mentioned
    # many times in Mozilla advisories
    PatternInFilePatternCheck(
        r"gb_mozilla_firefox_mfsa_\d{4}-\d{2,4}_lin\.nasl",
        r"Chancel\s+==>\s+Cancel",
    ),
    # Look like correct as this is also in dictionary_rare.txt
    PatternInFileCheck("deb_dla_2896.nasl", r"dependant\s+==>\s+dependent"),
    # Similar to the one above for e.g. SLES.
    # Also exclude "tre", because it's a package name.
    PatternInFilePatternCheck(
        r"mgasa-\d{4}-\d{4}\.nasl",
        r"(hda|tre|conexant)\s+==>\s+(had|tree|connexant)",
        file_pattern_flags=re.IGNORECASE,
    ),
    # Similar to the corrections above, with some additional
    # exclusions like e.g. names
    PatternsInFilePatternCheck(
        r"ELSA-\d{4}-\d{4,5}\.nasl",
        [
            (r"Stange\s+==>\s+Strange", 0),
            (r"chang\s+==>\s+change, charge", 0),
            (r"IST\s+==>\s+IS, IT, ITS, IT'S, SIT, LIST", 0),
            (r"hda\s+==>\s+had", 0),
            (r"Readded\s+==>\s+Read", 0),
            (r"ACI\s+==>\s+ACPI", re.IGNORECASE),
            (r"UE\s+==>\s+USE, DUE", 0),
        ],
    ),
    # NAM / nam is the abbreviation of these products. In
    # netop_infopublic.nasl there is a "nam" parameter.
    PatternInFilePatternCheck(
        r"gb_((cisco|solarwinds)_nam|netiq_access_manager)_",
        r"nam\s+==>\s+name",
        text_pattern_flags=re.IGNORECASE,
    ),
    PatternInFileCheck(
        "/netop_infopublic.nasl", r"nam\s+==>\s+name", flags=re.IGNORECASE
    ),
    # Product names used in a few VTs (no re.IGNORECASE is expected)
    PatternsCheck([r"renderD\s+==>\s+rendered", r"VertX\s+==>\s+vertex"]),
    PatternInFileCheck("_vertx_", r"vertx\s+==>\s+vertex"),
    # This is a class name of Tomcat which is getting checked / mentioned in
    # these, e.g.:
    # org.apache.juli.AsyncFileHandler.directory
    # JULI logging
    PatternInFileCheck("/Tomcat/tomcat_", r"juli\s+==>\s+july"),
    PatternInFileCheck("tomcat", r"JULI\s+==>\s+JULY"),
    # Some valid abbreviation for e.g. Cisco or VLC VTs
    PatternInFileCheck("caf", r"CAF\s+==>\s+CALF"),
]


class CheckSpelling(FilesPlugin):
    name = "check_spelling"

    def _parse_codespell_line(self, line: str) -> Tuple[str, str]:
        if not "==>" in line:
            raise ValueError("Invalid codespell line")

        file, _, correction = line.split(":")

        return file, correction.strip()

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
                "--uri-ignore-words-list=*",
            ] + files_parameters

            with redirect_stdout(io.StringIO()) as codespell_stream:
                codespell_main(*codespell_arguments)

            codespell_output = codespell_stream.getvalue()

            if "Traceback (most recent call last):" in codespell_output:
                yield LinterError(
                    codespell_output,
                    plugin=self.name,
                )

                continue

            codespell_entries = [
                line
                for line in codespell_output.splitlines()
                if not handle_linguistic_checks(
                    *self._parse_codespell_line(line), exceptions
                )
            ]

            for codespell_entry in codespell_entries:
                if "==>" in codespell_entry:
                    yield LinterError(
                        codespell_entry,
                        file=codespell_entry.split(":")[0],
                        plugin=self.name,
                    )

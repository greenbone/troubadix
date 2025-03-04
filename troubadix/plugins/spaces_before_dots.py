# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG
import re
from collections.abc import Iterator
from pathlib import Path

from troubadix.helper import CURRENT_ENCODING
from troubadix.helper.helper import is_ignore_file
from troubadix.helper.patterns import (
    ScriptTag,
    get_script_tag_pattern,
)
from troubadix.plugin import (
    FileContentPlugin,
    LinterFix,
    LinterResult,
    LinterWarning,
)

TAGS = [
    ScriptTag.SUMMARY,
    ScriptTag.VULDETECT,
    ScriptTag.INSIGHT,
    ScriptTag.IMPACT,
    ScriptTag.AFFECTED,
    ScriptTag.SOLUTION,
]

# Regex pattern to match:
# 1. A dot preceded and/or followed by any whitespace character (floating between words)
# 2. A dot preceded by any whitespace character at the end of the string
PATTERN = re.compile(r"\s+\.(\s|$)")
IGNORE = [
    # 21.04 and 22.04 are generated and should not be touched manually
    "21.04/",
    "22.04/",
    # uses dots for beginning of entry in enumeration
    "common/2008/debian/deb_246.nasl",
    "common/2008/debian/deb_266.nasl",
    "common/2008/freebsd/freebsd_5e92e8a2.nasl",
    "common/2008/freebsd/freebsdsa_cpio.nasl",
    "common/2008/freebsd/freebsdsa_cvs2.nasl",
    "common/2009/osc_photoGallery_sql_injection.nasl",
    "common/2009/gb_novell_edir_mult_vuln_jul09_lin.nasl",
    "common/2009/gb_novell_edir_mult_vuln_jul09_win.nasl",
    "common/2010/freebsd/freebsd_3a7c5fc4.nasl",
    "common/2012/freebsd/freebsd_a4a809d8.nasl",
    "common/2015/amazon/alas-2014-455.nasl",
    "common/2015/gb_mozilla_firefox_mult_vuln01_mar15_macosx.nasl",
    "common/2015/gb_mozilla_firefox_mult_vuln01_mar15_win.nasl",
    "common/2015/oracle/ELSA-2009-1619.nasl",
    "common/2015/oracle/ELSA-2011-0586.nasl",
    "common/2016/gb_perl_privilege_escalation_vuln_win.nasl",
    "common/2021/dropbear/gb_dropbear_ssh_filename_vuln_may20.nasl",
    "common/2021/eclipse/gb_jetty_GHSA-v7ff-8wcx-gmc5_lin.nasl",
    "common/2021/eclipse/gb_jetty_GHSA-v7ff-8wcx-gmc5_win.nasl",
    "common/gsf/2009/mandriva/gb_mandriva_MDVSA_2008_140.nasl",
    "common/gsf/2009/mandriva/gb_mandriva_MDVSA_2008_141.nasl",
    "common/gsf/2010/mandriva/gb_mandriva_MDVA_2010_173.nasl",
    "common/gsf/2010/mandriva/gb_mandriva_MDVSA_2010_155.nasl",
    "common/gsf/2010/mandriva/gb_mandriva_MDVSA_2010_155_1.nasl",
    "common/gsf/2010/mandriva/gb_mandriva_MDVSA_2010_167.nasl",
    "common/gsf/2020/f5/gb_f5_big_ip_K11315080.nasl",
    "common/gsf/2020/f5/gb_f5_big_iq_K11315080.nasl",
    "common/2022/opensuse/gb_opensuse_2022_1548_1.nasl",
    "common/2024/opensuse/gb_opensuse_2023_3247_1.nasl",
    "common/attic/debian/deb_232_1.nasl",
]


class CheckSpacesBeforeDots(FileContentPlugin):
    name = "check_spaces_before_dots"

    def check_content(
        self, nasl_file: Path, file_content: str
    ) -> Iterator[LinterResult]:
        """
        This plugin checks for excess whitespace before a dot
        in script_tags that have full sentence values
        """
        self.matches = []
        if nasl_file.suffix == ".inc" or is_ignore_file(nasl_file, IGNORE):
            return
        for tag in TAGS:
            pattern = get_script_tag_pattern(tag)
            match = pattern.search(file_content)
            if not match:
                continue

            value = match.group("value")
            value_start = match.start("value")

            for excess_match in PATTERN.finditer(value):
                whitespace_pos = excess_match.start() + value_start
                self.matches.append((whitespace_pos, excess_match.group()))
                fullmatch = match.group()
                yield LinterWarning(
                    f"value of script_tag {match.group('name')} has at least"
                    " one occurence of excess whitespace before a dot:"
                    f"\n '{fullmatch}'",
                    file=nasl_file,
                    plugin=self.name,
                )

    def fix(self) -> Iterator[LinterResult]:

        if not self.matches:
            return

        # Sort matches by position, descending order to avoid messing up indices during replacement
        self.matches.sort(reverse=True)

        file_content = self.context.file_content
        for pos, match_str in self.matches:
            # Replace the match by removing the excess whitespace before the dot
            fixed_str = re.sub(r"\s+\.", ".", match_str)
            file_content = (
                file_content[:pos]
                + fixed_str
                + file_content[pos + len(match_str) :]
            )

        with open(self.context.nasl_file, "w", encoding=CURRENT_ENCODING) as f:
            f.write(file_content)

        yield LinterFix(
            "Excess spaces were removed",
            file=self.context.nasl_file,
            plugin=self.name,
        )

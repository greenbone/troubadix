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
from typing import AnyStr, Iterator, List, Tuple, Union

from troubadix.plugin import FilePlugin, LinterError, LinterResult


def get_grammer_pattern() -> re.Pattern:
    return re.compile(
        r".*("
        r"refer\s+(the\s+)?Reference|"
        r"\s+an?\s+(multiple|errors)|"
        r"the\s+(References?\s+link|multiple\s+flaw)|"
        r"multiple\s+(unknown\s+)?("
        r"vulnerability|flaw|error|problem|issue|feature)\s+|"
        r"\s+(with\s+with|and\s+and|this\s+this|for\s+for|as\s+as|a\s+a"
        r"|of\s+of|to\s+to|an\s+an|the\s+the|is\s+is|in\s+in|are\s+are|have"
        r"\s+have|has\s+has|that\s+that)\s+|"
        r"vulnerabilit(y|ies)\s+vulnerabilit(y|ies)|"
        r"links\s+mentioned\s+in(\s+the)?\s+reference|"
        r"\s+an?(\s+remote)?(\s+(un)?authenticated)?\s+attackers|"
        # e.g. "this flaws"
        r"this\s+(vulnerabilities|(flaw|error|problem|issue|feature|file)s)|"
        # e.g. "these flaw "
        r"these\s+(vulnerability|(flaw|error|problem|issue|feature|file)\s+)|"
        r"\s+or\s+not\.?(\"\);)?$|"
        r"from(\s+the)?(\s+below)?mentioned\s+References?\s+link|"
        r"software\s+it\s+fail|"
        r"references\s+(advisor|link)|"
        r"The\s+multiple\s+(vulnerabilit|flaw|error|problem|issue|feature)|"
        r"(vulnerability|flaw|error|problem|issue|feature)\s+exist\s+|"
        r"(vulnerabilitie|flaw|error|problem|issue|feature)s\s+exists|"
        r"multiple\s+[^\s]+((and\s+)?[^\s]+)?\s+("
        r"vulnerability|flaw|error|problem|issue|feature)\s+|"
        r"(\s+|^|\"|- )A\s+[^\s]*((and\s+)?[^\s]+\s+)?("
        r"vulnerabilitie|flaw|error|problem|issue)s|"
        r"(\s+|^|\"|- )An?\+(unspecified|multiple|unknown)\s+("
        r"vulnerabilitie|flaw|error|problem|issue)s|"
        r"is\s+(prone|vulnerable|affected)\s+(to|by)\s+("
        r"unspecified|XML\s+External\s+Entity|integer\s+(und|ov)erflow|"
        r"DLL\s+hijacking|(hardcoded?|default)\s+credentials?|open[\s-]+"
        r"redirect(ion)?|user\s+enumeration|arbitrary\s+file\s+read|memory"
        r"\s+corruption|use[\s-]+after[\s-]+free|man[\s-]+in[\s-]+the[\s-]"
        r"+middle(\s+attack)?|cross[\s-]+site[\s-]+(scripting(\s+\(XSS\))?"
        r"|request[\s-]+forgery(\s+\(CSRF\))?)|denial[\s-]+of[\s-]+service"
        r"|information\s+disclosure|(path|directory)\s+traversal|"
        r"(arbitrary\s+|remote\s+)?((code|command)\s+(execution|injection)"
        r"|file\s+inclusion)|SQL\s+injection|security|(local )?privilege"
        r"[\s-]+(escalation|elevation)|(authentication|security|access)"
        r"\s+bypass|(buffer|heap)\s+overflow)\s+vulnerability|"
        # e.g.:
        # "is prone a to denial of service (DoS) vulnerability"
        # "is prone an information disclosure vulnerability"
        r"\s+(is|are)\s+(prone|vulnerable|affected)\s+an?\s+|"
        # e.g. "is prone to a security bypass vulnerabilities"
        r"is\s+prone\s+to\s+an?\s+[^\s]+\s+([^\s]+\s+)?vulnerabilities" r").*",
        re.IGNORECASE,
    )


class CheckGrammar(FilePlugin):
    name = "check_grammar"

    def run(self) -> Iterator[LinterResult]:
        """This script checks the passed VT / Include for common grammar
        problems

        Args:
            nasl_file:    The VT / Include that is going to be checked
            file_content: The content of the file that is going to be
                          checked
        """
        pattern = get_grammer_pattern()

        for match in pattern.finditer(self.context.file_content):
            if match:
                if self.check_for_false_positives(
                    match.group(0), str(self.context.nasl_file)
                ):
                    continue

                yield LinterError(
                    "VT/Include has the following grammar problem:"
                    f" {match.group(0)}",
                    file=self.context.nasl_file,
                    plugin=self.name,
                )

    @staticmethod
    def check_for_false_positives(match: AnyStr, nasl_file: str) -> bool:
        """
        Checks for false positives in the findings.
        """

        # List of known false positives, valid entries are:
        # strings, regex patterns and Tuples
        # in the format of: (filename, content)
        known_fps = [
            re.compile(r"[Aa] few "),
            "a multiple keyboard ",
            "A A S Application Access Server",
            "a Common Vulnerabilities and Exposures",
            "an attackers choise",
            "multiple error handling vulnerabilities",
            # Like seen in 2022/debian/deb_dla_2981.nasl
            "a multiple concurrency",
            # From 2008/debian/deb_1017_1.nasl
            "Harald Welte discovered that if a process issues"
            " a USB Request Block (URB)",
            # From several Ubuntu LSCs like e.g.:
            # 2021/ubuntu/gb_ubuntu_USN_4711_1.nasl
            "An attacker with access to at least one LUN in a multiple",
            # nb: The regex to catch "this files" might catch this wrongly...
            re.compile(r"th(is|ese)\s+filesystem"),
            # Like seen in e.g. 2008/freebsd/freebsd_mod_php4-twig.nasl
            re.compile(r'(\s+|")[Aa]\s+multiple\s+of'),
            # WITH can be used like e.g. the following which is valid:
            # "with WITH stack unwinding"
            # see e.g. gb_sles_2021_3215_1.nasl or gb_sles_2021_2320_1.nasl
            re.compile(r"with\s+WITH"),
            # Valid sentences
            re.compile(r"these\s+error\s+(messages|reports|conditions)"),
            re.compile(r"these\s+file\s+(permissions|overwrites|names)"),
            (
                "2012/gb_VMSA-2010-0007.nasl",
                "e. VMware VMnc Codec heap overflow vulnerabilities\n\n"
                "  Vulnerabilities in the",
            ),
            # nb: Valid sentence
            ("gb_opensuse_2018_1900_1.nasl", "(Note that"),
        ]

        return any(
            [
                CheckGrammar._check_false_positive(fp, match, nasl_file)
                for fp in known_fps
            ]
        )

    @staticmethod
    def _check_false_positive(
        false_positive: List[Union[re.Pattern, str, Tuple[str, str]]],
        match: re.Match,
        nasl_filename: str,
    ) -> bool:
        if isinstance(false_positive, re.Pattern):
            return bool(false_positive.search(match))

        elif isinstance(false_positive, str):
            return false_positive in match

        elif isinstance(false_positive, tuple):
            filename, content_fp = false_positive
            return filename in nasl_filename and content_fp in match

        else:
            raise NotImplementedError(
                "Invalid type for false_positives entry. "
                "Valid types: str, re.Pattern, Tuple[str, str]"
            )

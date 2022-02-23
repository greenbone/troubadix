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

from naslinter.plugin import LinterError, FileContentPlugin, LinterResult


class CheckGrammar(FileContentPlugin):
    name = "check_grammar"

    @staticmethod
    def run(nasl_file: Path, file_content: str) -> Iterator[LinterResult]:
        """This script checks the passed VT / Include for common grammar
        problems

        Args:
            nasl_file:    The VT / Include that is going to be checked
            file_content: The content of the file that is going to be
                          checked
        """

        nasl_file_str = str(nasl_file)

        grammar_problems_pattern = (
            ".*("
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
            r"this\s+vulnerabilities|"
            r"these\s+vulnerability|"
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
            # e.g. "is prone to a security bypass vulnerabilities"
            r"is\s+prone\s+to\s+an?\s+[^\s]+\s+([^\s]+\s+)?vulnerabilities"
            ").*"
        )

        grammar_problems_report = (
            f"VT/Include '{nasl_file_str}' is having "
            "grammar problems in the following line(s):\n"
        )

        grammar_problem_match = re.finditer(
            grammar_problems_pattern, file_content, re.IGNORECASE
        )

        if grammar_problem_match is not None:
            for line in grammar_problem_match:
                if line:

                    # Exclude a few known false positives
                    if (
                        "a few " in line.group(0)
                        or "A few " in line.group(0)
                        or "a multiple keyboard " in line.group(0)
                    ):
                        continue

                    if "A A S Application Access Server" in line.group(0):
                        continue

                    if "a Common Vulnerabilities and Exposures" in line.group(
                        0
                    ):
                        continue

                    if "Multiple '/' Vulnerability" in line.group(0):
                        continue

                    if "an attackers choise" in line.group(0):
                        continue

                    if (
                        "2012/gb_VMSA-2010-0007.nasl" in nasl_file_str
                        and "e. VMware VMnc Codec heap overflow vulner"
                        "abilities\n\n  Vulnerabilities in the" in line.group(0)
                    ):
                        continue

                    # nb: Valid sentence
                    if (
                        "gb_opensuse_2018_1900_1.nasl" in nasl_file_str
                        and "(Note that" in line.group(0)
                    ):
                        continue

                    # same as above
                    if (
                        "gb_sles_2021_3215_1.nasl" in nasl_file_str
                        and "with\n WITH" in line.group(0)
                    ):
                        continue

                    # same as above
                    if (
                        "gb_sles_2021_2320_1.nasl" in nasl_file_str
                        and "with WITH" in line.group(0)
                    ):
                        continue

                    # same
                    if "multiple error handling vulnerabilities" in line.group(
                        0
                    ):
                        continue

                    # Like seen in e.g. 2008/freebsd/freebsd_mod_php4-twig.nasl
                    if re.search(r'(\s+|")[Aa]\s+multiple\s+of', line.group(0)):
                        continue

                    yield LinterError(
                        grammar_problems_report
                        + "Hit: "
                        + line.group(1)
                        + "\n"
                        + "Full line:"
                        + "\n"
                        + line.group(0)
                        + "\n"
                    )
            return

        return

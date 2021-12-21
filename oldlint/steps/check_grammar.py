#!/usr/bin/env python3

import re
import sys


def run(file):
    """This script checks the passed VT / Include for common grammar problems

    Args:
        file: The VT / Include that is going to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message

    """

    grammar_problems_pattern = ".*("
    grammar_problems_pattern += "refer\s+(the\s+)?Reference|"
    grammar_problems_pattern += "\s+an?\s+(multiple|errors)|"
    grammar_problems_pattern += "the\s+(References?\s+link|multiple\s+flaw)|"
    grammar_problems_pattern += "multiple\s+(unknown\s+)?(vulnerability|flaw|error|problem|issue|feature)\s+|"
    grammar_problems_pattern += "\s+(with\s+with|and\s+and|this\s+this|for\s+for|as\s+as|a\s+a|of\s+of|to\s+to|an\s+an|the\s+the|is\s+is|in\s+in|are\s+are|have\s+have|has\s+has|that\s+that)\s+|"
    grammar_problems_pattern += "vulnerabilit(y|ies)\s+vulnerabilit(y|ies)|"
    grammar_problems_pattern += "links\s+mentioned\s+in(\s+the)?\s+reference|"
    grammar_problems_pattern += (
        "\s+an?(\s+remote)?(\s+(un)?authenticated)?\s+attackers|"
    )
    grammar_problems_pattern += "this\s+vulnerabilities|"
    grammar_problems_pattern += "these\s+vulnerability|"
    grammar_problems_pattern += '\s+or\s+not\.?("\);)?$|'
    grammar_problems_pattern += (
        "from(\s+the)?(\s+below)?mentioned\s+References?\s+link|"
    )
    grammar_problems_pattern += "software\s+it\s+fail|"
    grammar_problems_pattern += "references\s+(advisor|link)|"
    grammar_problems_pattern += (
        "The\s+multiple\s+(vulnerabilit|flaw|error|problem|issue|feature)|"
    )
    grammar_problems_pattern += (
        "(vulnerability|flaw|error|problem|issue|feature)\s+exist\s+|"
    )
    grammar_problems_pattern += (
        "(vulnerabilitie|flaw|error|problem|issue|feature)s\s+exists|"
    )
    grammar_problems_pattern += "multiple\s+[^\s]+((and\s+)?[^\s]+)?\s+(vulnerability|flaw|error|problem|issue|feature)\s+|"
    grammar_problems_pattern += '(\s+|^|"|- )A\s+[^\s]*((and\s+)?[^\s]+\s+)?(vulnerabilitie|flaw|error|problem|issue)s|'
    grammar_problems_pattern += '(\s+|^|"|- )An?\+(unspecified|multiple|unknown)\s+(vulnerabilitie|flaw|error|problem|issue)s|'
    grammar_problems_pattern += "is\s+(prone|vulnerable|affected)\s+(to|by)\s+(unspecified|XML\s+External\s+Entity|integer\s+(und|ov)erflow|DLL\s+hijacking|(hardcoded?|default)\s+credentials?|open[\s-]+redirect(ion)?|user\s+enumeration|arbitrary\s+file\s+read|memory\s+corruption|use[\s-]+after[\s-]+free|man[\s-]+in[\s-]+the[\s-]+middle(\s+attack)?|cross[\s-]+site[\s-]+(scripting(\s+\(XSS\))?|request[\s-]+forgery(\s+\(CSRF\))?)|denial[\s-]+of[\s-]+service|information\s+disclosure|(path|directory)\s+traversal|(arbitrary\s+|remote\s+)?((code|command)\s+(execution|injection)|file\s+inclusion)|SQL\s+injection|security|(local )?privilege[\s-]+(escalation|elevation)|(authentication|security|access)\s+bypass|(buffer|heap)\s+overflow)\s+vulnerability"
    grammar_problems_pattern += ").*"

    grammar_problems_report = (
        "VT/Include '"
        + str(file)
        + "' is having grammar problems in the following line(s):\n"
    )
    text = open(file, encoding="latin-1").read()
    grammar_problems_found = False

    grammar_problem_match = re.finditer(
        grammar_problems_pattern, text, re.IGNORECASE
    )

    if grammar_problem_match is not None:
        for line in grammar_problem_match:
            if line is not None and line.group(0) is not None:

                # Exclude a few known false positives
                if (
                    "a few " in line.group(0)
                    or "A few " in line.group(0)
                    or "a multiple of" in line.group(0)
                    or "a multiple keyboard " in line.group(0)
                ):
                    continue

                if "A A S Application Access Server" in line.group(0):
                    continue

                if "a Common Vulnerabilities and Exposures" in line.group(0):
                    continue

                if "Multiple '/' Vulnerability" in line.group(0):
                    continue

                if "an attackers choise" in line.group(0):
                    continue

                if (
                    "2012/gb_VMSA-2010-0007.nasl" in file
                    and "e. VMware VMnc Codec heap overflow vulnerabilities\n\n  Vulnerabilities in the"
                    in line.group(0)
                ):
                    continue

                # nb: Valid sentence
                if (
                    "gb_opensuse_2018_1900_1.nasl" in file
                    and "(Note that" in line.group(0)
                ):
                    continue

                # same as above
                if (
                    "gb_sles_2021_3215_1.nasl" in file
                    and "with\n WITH" in line.group(0)
                ):
                    continue

                # same
                if "multiple error handling vulnerabilities" in line.group(0):
                    continue

                grammar_problems_report = (
                    grammar_problems_report
                    + "Hit: "
                    + line.group(1)
                    + "\n"
                    + "Full line:"
                    + "\n"
                    + line.group(0)
                    + "\n"
                )
                grammar_problems_found = True

    if grammar_problems_found:
        return -1, grammar_problems_report

    return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = run(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        ci_helpers.report("VTs/Includes having grammar problems", error)
        sys.exit(1)

    sys.exit(0)

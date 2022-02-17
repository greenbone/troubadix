#!/usr/bin/env python3

import re
from pathlib import Path
from typing import Iterator

from naslinter.plugin import LinterError, FileContentPlugin, LinterResult


class CheckCopyrightText(FileContentPlugin):
    name = "check_copyright_text"

    @staticmethod
    def run(nasl_file: Path, file_content: str) -> Iterator[LinterResult]:
        """This step checks a VT for the correct use of the copyright text.

        Prior to this step, most VTs are using
        "This script is Copyright (C) [...]",
        however the introductory text ("This script is") is to be discarded
        from now on.

        In addition it will also report any occurrence of the following
        outdated text pattern:

        # Text descriptions are largely excerpted from the referenced
        # advisory, and are Copyright (C) of their respective author(s)

        or:

        # Text descriptions are largely excerpted from the referenced
        # advisory, and are Copyright (C) the respective author(s)

        or:

        # Text descriptions are largely excerpted from the referenced
        # advisory, and are Copyright (C) the respective author(s)

        or:

        # Some text descriptions might be excerpted from the referenced
        # advisories, and are Copyright (C) by the respective right holder(s)

        which should be the following from now on:

        # Some text descriptions might be excerpted from (a) referenced
        # source(s), and are Copyright (C) by the respective right holder(s).
        """

        if not re.search(
            r'script_copyright\("Copyright \(C\) [0-9]{4}', file_content
        ):
            yield LinterError(
                "The VT is using an incorrect syntax for its copyright "
                "statement. Please start (EXACTLY) with:\n"
                "'script_copyright(\"Copyright (C)' followed by the year "
                "(matching the one in creation_date) and the author/company."
            )

        if re.search(
            r"^# (Text descriptions are largely excerpted from the referenced"
            r"\n# advisory, and are Copyright \([cC]\) (of )?(the|their) resp"
            r"ective author\(s\)|Some text descriptions might be excerpted from"
            r" the referenced\n# advisories, and are Copyright \(C\) by the "
            r"respective right holder\(s\))",
            file_content,
            re.MULTILINE,
        ):
            yield LinterError(
                "The VT is using an incorrect copyright statement. Please "
                "use (EXACTLY):\n\n"
                "# Some text descriptions might be excerpted from (a) "
                "referenced\n# source(s), and are Copyright (C) by the "
                "respective right holder(s).\n"
            )

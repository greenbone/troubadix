# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG

import re
from pathlib import Path
from typing import Iterator

from troubadix.plugin import FileContentPlugin, LinterResult, LinterWarning

FOREACH_PATTERN = re.compile(r"foreach\s+(?P<ident>\w+)\s*\((?P<iter>.+)\)")
MAKE_LIST_PATTERN = re.compile(
    r"^(?:make_list|make_list_unique)\((?P<params>.+)\)$"
)


class CheckVariableRedefinitionInForeach(FileContentPlugin):
    name = "check_variable_redefinition_in_foreach"

    def check_content(
        self, nasl_file: Path, file_content: str
    ) -> Iterator[LinterResult]:
        """This plugin checks for a redefinition of the variable
        that is passed to the foreach loop.
        This can be caused by using same variable name
        for both the list and the element being iterated over.
        Incorrect uses of foreach loops that are covered by this plugin are:
        foreach foo(foo){}
        foreach foo(make_list(bar,foo)){}
        foreach foo(make_list_unique(bar,foo)){}
        """

        for foreach_match in FOREACH_PATTERN.finditer(file_content):
            identifier = foreach_match.group("ident")

            # replace instead of strip, because the iterator can contain
            # whitespace as part of the expression.
            # Saving from further strip calls
            # make_list( bar , foo )
            iterator = foreach_match.group("iter").replace(" ", "")

            if make_list_match := MAKE_LIST_PATTERN.fullmatch(iterator):
                make_list_params = make_list_match.group("params").split(",")
                if identifier in make_list_params:
                    yield LinterWarning(
                        f"The variable '{identifier}' "
                        f"is used as identifier and\n"
                        f"as part of the iterator in the"
                        f" same foreach loop\n'{foreach_match.group()}'",
                        plugin=self.name,
                        file=nasl_file,
                    )
            else:
                if identifier == iterator:
                    yield LinterWarning(
                        f"The variable '{identifier}' is redefined "
                        f"by being the identifier\nand the iterator in the"
                        f" same foreach loop '{foreach_match.group()}'",
                        plugin=self.name,
                        file=nasl_file,
                    )

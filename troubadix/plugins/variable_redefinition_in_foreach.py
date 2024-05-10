# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG

import re
from pathlib import Path
from typing import Iterator

from troubadix.plugin import FileContentPlugin, LinterResult, LinterWarning

foreach_pattern = re.compile(r"foreach\s+(\w+)\s*\((.+)\)")
make_list_pattern = re.compile(r"^(?:make_list|make_list_unique)\((.+)\)$")


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

        for foreach_match in foreach_pattern.finditer(file_content):
            identifier = foreach_match.group(1)
            iterator = foreach_match.group(2).replace(" ", "")

            if make_list_match := make_list_pattern.fullmatch(iterator):
                make_list_params = make_list_match.group(1).split(",")
                if identifier in make_list_params:
                    yield LinterWarning(
                        f"The variable '{foreach_match.group(1)}' "
                        f"is used as identifier and\n"
                        f"as part of the iterator in the"
                        f" same foreach loop\n'{foreach_match.group()}'",
                        plugin=self.name,
                        file=nasl_file,
                    )
            else:
                if identifier == iterator:
                    yield LinterWarning(
                        f"The variable '{foreach_match.group(1)}' is redefined "
                        f"by being the identifier\nand the iterator in the"
                        f" same foreach loop '{foreach_match.group()}'",
                        plugin=self.name,
                        file=nasl_file,
                    )

# Copyright (C) 2022 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# pylint: disable=fixme

from enum import IntEnum
import re

from pathlib import Path
from typing import Iterator, Union

from naslinter.plugin import (
    LinterError,
    FileContentPlugin,
    LinterResult,
)
from naslinter.helper import get_root, get_special_tag_pattern

# See https://shorturl.at/jBGJT for a list of the category numbers.
class VTCategory(IntEnum):
    ACT_INIT = 0
    ACT_SCANNER = 1
    ACT_SETTINGS = 2
    ACT_GATHER_INFO = 3
    ACT_ATTACK = 4
    ACT_MIXED_ATTACK = 5
    ACT_DESTRUCTIVE_ATTACK = 6
    ACT_DENIAL = 7
    ACT_KILL_HOST = 8
    ACT_FLOOD = 9
    ACT_END = 10


def check_category(
    content: str, script: str = ""
) -> Union[LinterError, VTCategory]:
    """Check if the content contains a script category
    Arguments:
        content         the content to check

    Returns:
        LinterError     if no category found or category invalid
        VTCategory      else
    """
    match = get_special_tag_pattern(name="category", flags=re.MULTILINE).search(
        content
    )

    if not match:
        return LinterError(f"{script}: Script category is missing.")

    category_value = match.group("value")
    if category_value not in dir(VTCategory):
        return LinterError(
            f"{script}: Script category {category_value} is unsupported."
        )

    return VTCategory[category_value]


class CheckDependencyCategoryOrder(FileContentPlugin):
    name = "check_dependency_category_order"

    @staticmethod
    def run(nasl_file: Path, file_content: str) -> Iterator[LinterResult]:
        """No VT N should depend on scripts that are in a category that
        normally would be executed after the category of VT M.
        e.g. a VT N within the ACT_GATHER_INFO category (3) is
        not allowed to depend on a VT M within the ACT_ATTACK category (4).
        See https://shorturl.at/jBGJT for a list of such category numbers.

        In addition it is not allowed for VTs to have a direct dependency
        to VTs from within the ACT_SCANNER category.
        """
        root = get_root()
        """No VT should depend on other VTs that are marked as deprecated via:

        script_tag(name:"deprecated", value:TRUE);
        exit(66);

        """

        matches = get_special_tag_pattern(
            name="dependencies", flags=re.MULTILINE
        ).finditer(file_content)
        if not matches:
            return

        deprecated_pattern = re.compile(
            r"^\s*exit\s*\(\s*66\s*\)\s*;|script_tag\s*\(\s*name\s*:\s*[\"']"
            r"deprecated[\"']\s*,\s*value\s*:\s*TRUE\s*\)\s*;",
            re.MULTILINE,
        )
        deprecated = re.search(deprecated_pattern, file_content)
        if deprecated:
            return

        error = ""
        debug = ""

        for dependencies_match in matches:
            if (
                dependencies_match is not None
                and dependencies_match.group(1) is not None
            ):

                dependencies = dependencies_match.group(1)

                # Remove single and/or double quotes, spaces
                # and create a list by using the comma as a separator
                # TODO: find a better way for this as it would miss something like the following broken dependencies:
                # script_dependencies("redax  script_detect.nasl");
                # script_dependencies("redax'script_detect.nasl");
                dep_list = re.sub(r'[\'"\s]', "", dependencies).split(",")
                for dep in dep_list:

                    # TODO: gsf/PCIDSS/PCI-DSS.nasl, gsf/PCIDSS/v2.0/PCI-DSS-2.0.nasl and GSHB/EL15/GSHB.nasl
                    # are using a variable which we currently can't handle.
                    if "+d+.nasl" in dep:
                        continue

                    if not os.path.exists(
                        os.path.join("scripts", dep)
                    ) and not os.path.exists(dep):
                        debug += (
                            "\n\t"
                            + str(dep)
                            + " (dependency of "
                            + str(file)
                            + " missing on the filesystem)"
                        )
                        continue

                    dep_text = ""

                    if os.path.exists(os.path.join("scripts", dep)):
                        dep_text = open(
                            os.path.join("scripts", dep), encoding="latin-1"
                        ).read()
                    elif os.path.exists(dep):
                        dep_text = open(dep, encoding="latin-1").read()
                    else:
                        continue

                    dep_deprecated_matches = re.finditer(
                        deprecated_re, dep_text
                    )
                    if dep_deprecated_matches is not None:
                        tmp_error = ""
                        for dep_deprecated_match in dep_deprecated_matches:
                            if (
                                dep_deprecated_match is not None
                                and dep_deprecated_match.group(1) is not None
                            ):
                                tmp_error += "\n\t" + str(
                                    dep_deprecated_match.group(0)
                                )

                        if tmp_error:
                            error += (
                                "\n\t"
                                + str(file)
                                + " depends on "
                                + str(dep)
                                + " which is marked as deprecated in the following line(s):"
                                + tmp_error
                            )

        if error:
            return -1, str(error)

        if debug:
            return (
                1,
                "No check for deprecated dependencies possible due to VTs using a dependency which doesn't exist on the local filesystem:"
                + str(debug),
            )

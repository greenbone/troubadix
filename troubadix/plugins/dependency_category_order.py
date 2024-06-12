# Copyright (C) 2022 Greenbone AG
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

import re
from enum import IntEnum
from pathlib import Path
from typing import Iterator, Union

from troubadix.helper import CURRENT_ENCODING, SpecialScriptTag
from troubadix.helper.helper import FEED_VERSIONS
from troubadix.helper.patterns import get_special_script_tag_pattern
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


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


class CategoryError(Exception):
    pass


def check_category(
    content: str, pattern: re.Pattern, script: str
) -> Union[LinterError, VTCategory]:
    """Check if the content contains a script category
    Arguments:
        content         the content to check

    Returns:
        LinterError     if no category found or category invalid
        VTCategory      else
    """
    match = pattern.search(content)

    if not match:
        raise CategoryError(
            f"{script}: Script category is missing or unsupported."
        )

    category_value = match.group("value")
    try:
        return VTCategory[category_value]
    except ValueError:
        raise CategoryError(
            f"{script}: Script category {category_value} is unsupported."
        ) from None


class CheckDependencyCategoryOrder(FileContentPlugin):
    name = "check_dependency_category_order"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """No VT N should depend on scripts that are in a category that
        normally would be executed after the category of VT M.
        e.g. a VT N within the ACT_GATHER_INFO category (3) is
        not allowed to depend on a VT M within the ACT_ATTACK category (4).
        See https://shorturl.at/jBGJT for a list of such category numbers.

        In addition it is not allowed for VTs to have a direct dependency
        to VTs from within the ACT_SCANNER category.
        """
        if (
            nasl_file.suffix == ".inc"
            or not "script_dependencies(" in file_content
            or "# troubadix: disable=template_nd_test_files_fps" in file_content
        ):
            return

        category_pattern = get_special_script_tag_pattern(
            SpecialScriptTag.CATEGORY
        )

        try:
            category = check_category(
                content=file_content,
                pattern=category_pattern,
                script=nasl_file.name,
            )
        except CategoryError as e:
            yield LinterError(
                str(e),
                file=nasl_file,
                plugin=self.name,
            )
            return

        dependencies_pattern = get_special_script_tag_pattern(
            SpecialScriptTag.DEPENDENCIES
        )
        matches = dependencies_pattern.finditer(file_content)

        if not matches:
            return

        root = self.context.root

        for match in matches:
            if match:
                # Remove single and/or double quotes, spaces
                # and create a list by using the comma as a separator
                dependencies = re.sub(
                    r'[\'"\s]', "", match.group("value")
                ).split(",")

                for dep in dependencies:
                    dependency_path = None
                    for vers in FEED_VERSIONS:
                        if (root / vers / dep).exists():
                            dependency_path = root / vers / dep

                    if not dependency_path:
                        yield LinterError(
                            f"The script dependency {dep} could not "
                            "be found within the VTs.",
                            file=nasl_file,
                            plugin=self.name,
                        )
                    else:
                        dependency_content = dependency_path.read_text(
                            encoding=CURRENT_ENCODING
                        )

                        try:
                            dependency_category = check_category(
                                content=dependency_content,
                                pattern=category_pattern,
                                script=dependency_path.name,
                            )
                        except CategoryError as e:
                            yield LinterError(
                                str(e),
                                file=nasl_file,
                                plugin=self.name,
                            )

                        if category.value < dependency_category.value:
                            yield LinterError(
                                f"Script category {category.name}"
                                f"({category.value}) is lower than "
                                f"the category {dependency_category.name}"
                                f"({dependency_category.value}) of the "
                                f"dependency {dep}.",
                                file=nasl_file,
                                plugin=self.name,
                            )
                        # nb: Currently not sure about the
                        # host_alive_detection.nasl dependency so
                        # excluding them for now.
                        if (
                            dependency_category.name == "ACT_SCANNER"
                            and dep != "host_alive_detection.nasl"
                        ):
                            yield LinterError(
                                f"Script depends on {dep} which has the "
                                f"category {dependency_category.name}"
                                f"({dependency_category.value}), but no VT"
                                " is allowed to have a direct dependency "
                                "to VTs in this category.",
                                file=nasl_file,
                                plugin=self.name,
                            )

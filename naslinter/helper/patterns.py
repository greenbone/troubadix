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

import re

# regex patterns for script tags
_TAG_PATTERN = (
    r'script_tag\(\s*name\s*:\s*["\'](?P<name>{name})["\']\s*,'
    r'\s*value\s*:\s*["\']?(?P<value>{value})["\']?\s*\)\s*;'
)

_SPECIAL_TAG_PATTERN = (
    r'script_(?P<name>{name})\s*\(["\']?(?P<value>{value})["\']?\s*\)\s*;'
)


def get_tag_pattern(
    name: str, *, value: str = r".+", flags: re.RegexFlag = 0
) -> re.Pattern:
    """
    The returned pattern catchs all `script_tags(name="", value="");`

    Arguments:
        name        script tag name
        value       script tag value (default: at least on char)
        flags       regex flags for compile (default: 0)

    The returned `Match`s by this pattern will have group strings
    .group('name') and .group('value')
    Returns
        `re.Pattern` object
    """
    return re.compile(_TAG_PATTERN.format(name=name, value=value), flags=flags)


def get_special_tag_pattern(
    name: str, *, value: str = r".+", flags: re.RegexFlag = 0
) -> re.Pattern:
    """
    The returned pattern catchs all `script_<name>(<value>);`

    Arguments:
        name        script tag name
        value       script tag value (default: at least on char)
        flags       regex flags for compile (default: 0)

    The returned `Match`s by this pattern will have group strings
    .group('name') and .group('value')
    Returns
        `re.Pattern` object
    """
    return re.compile(
        _SPECIAL_TAG_PATTERN.format(name=name, value=value), flags=flags
    )


class SpecialScriptTagPatterns:
    instance = False

    def __init__(self) -> None:
        self.dependencies = get_special_tag_pattern(
            name="dependencies", flags=re.MULTILINE
        )
        self.instance = self


def get_dependency_tag_pattern() -> SpecialScriptTagPatterns:
    if SpecialScriptTagPatterns.instance:
        return SpecialScriptTagPatterns.instance.dependencies
    return SpecialScriptTagPatterns().dependencies

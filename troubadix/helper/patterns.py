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
from enum import Enum
from typing import OrderedDict

# regex patterns for script tags
_TAG_PATTERN = (
    r'script_tag\s*\(\s*name\s*:\s*["\'](?P<name>{name})["\']\s*,'
    r'\s*value\s*:\s*["\']?(?P<value>{value})["\']?\s*\)\s*;'
)


class ScriptTag(Enum):
    AFFECTED = "affected"
    CREATION_DATE = "creation_date"
    CVSS_BASE = "cvss_base"
    CVSS_BASE_VECTOR = "cvss_base_vector"
    DEPRECATED = "deprecated"
    IMPACT = "impact"
    INSIGHT = ("insight",)
    LAST_MODIFICATION = "last_modification"
    QOD = "qod"
    QOD_TYPE = "qod_type"
    SEVERITY_VECTOR = "severity_vector"
    SEVERITY_ORIGIN = "severity_origin"
    SEVERITY_DATE = "severity_date"
    SOLUTION = "solution"
    SOLUTION_TYPE = "solution_type"
    SUMMARY = "summary"
    VULDETECT = "vuldetect"


def _get_tag_pattern(
    name: str, *, value: str = r".+?", flags: re.RegexFlag = 0
) -> re.Pattern:
    """
    The returned pattern catches all `script_tags(name="", value="");`

    Arguments:
        name        a SpecialScriptTag Enum type
        value       script tag value (default: at least on char)
        flags       regex flags for compile (default: 0)

    The returned `Match`s by this pattern will have group strings
    .group('name') and .group('value')
    Returns
        `re.Pattern` object
    """
    return re.compile(_TAG_PATTERN.format(name=name, value=value), flags=flags)


class ScriptTagPatterns:
    def __init__(self) -> None:
        self.pattern = OrderedDict()
        for tag in ScriptTag:
            flags = 0
            if tag.value == "deprecated":
                value = r"TRUE"
            elif tag.value == "cvss_base_vector":
                value = r"AV:[LAN]/AC:[HML]/Au:[NSM]/C:[NPC]/I:[NPC]/A:[NPC]"
            elif tag.value == "cvss_base":
                value = r"(10\.0|[0-9]\.[0-9])"
            elif tag.value in ["creation_date", "modification_date"]:
                value = r"[A-Za-z0-9\:\-\+\,\s\(\)]{44}"
            else:
                value = r".+?"
                flags = re.MULTILINE | re.DOTALL
            self.pattern[tag.value] = _get_tag_pattern(
                name=tag.value, value=value, flags=flags
            )


_XREF_TAG_PATTERN = (
    r'script_xref\(\s*name\s*:\s*["\'](?P<type>{type})["\']\s*,'
    r'\s*value\s*:\s*["\']?(?P<value>{value})["\']?\s*\)\s*;'
)


def get_xref_pattern(
    name: str,
    *,
    value: str = r".+",
    flags: re.RegexFlag = 0,
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
    return re.compile(
        _XREF_TAG_PATTERN.format(type=name, value=value),
        flags=flags,
    )


def get_tag_pattern(
    name: ScriptTag,
    *,
    value: str = r".+",
    flags: re.RegexFlag = 0,
) -> re.Pattern:
    """
    The returned pattern catches all `script_<name>(<value>);`

    Arguments:
        name        script tag name
        value       script tag value (default: at least on char)
        flags       regex flags for compile (default: 0)

    The returned `Match`s by this pattern will have group strings
    .group('name') and .group('value')
    Returns
        `re.Pattern` object
    """
    # if not value:
    #     return ScriptTagPatterns().pattern[name.value]
    if not value:
        if name.value == "deprecated":
            value = r"TRUE"
        elif name.value == "cvss_base_vector":
            value = r"AV:[LAN]/AC:[HML]/Au:[NSM]/C:[NPC]/I:[NPC]/A:[NPC]"
        elif name.value == "cvss_base":
            value = r"(10\.0|[0-9]\.[0-9])"
    return _get_tag_pattern(name=name.value, value=value, flags=flags)


_SPECIAL_TAG_PATTERN = (
    r'script_(?P<name>{name})\s*\(["\']?(?P<value>{value})["\']?\s*\)\s*;'
)


class SpecialScriptTag(Enum):
    ADD_PREFERENCE = "add_preference"
    BUGTRAQ_ID = "bugtraq_id"
    CATEGORY = "category"
    COPYRIGHT = "copyright"
    CVE_ID = "cve_id"
    DEPENDENCIES = "dependencies"
    EXCLUDE_KEYS = "exclude_keys"
    FAMILY = "family"
    MANDATORY_KEYS = "mandatory_keys"
    NAME = "name"
    OID = "oid"
    REQUIRE_KEYS = "require_keys"
    REQUIRE_PORTS = "require_ports"
    REQUIRE_UDP_PORTS = "require_udp_ports"
    VERSION = "version"
    XREF = "xref"


def _get_special_tag_pattern(
    name: str, *, value: str = r".+?", flags: re.RegexFlag = 0
) -> re.Pattern:
    return re.compile(
        _SPECIAL_TAG_PATTERN.format(name=name, value=value), flags=flags
    )


class SpecialScriptTagPatterns:
    def __init__(self) -> None:
        self.pattern = OrderedDict()
        for tag in SpecialScriptTag:
            if tag.value == "xref":
                self.pattern[tag.value] = re.compile(
                    _XREF_TAG_PATTERN.format(
                        name=tag.value, value=r".+?", type="URL"
                    ),
                )
            elif tag.value == "oid":
                self.pattern[tag.value] = _get_special_tag_pattern(
                    name=tag.value, value=r'\s*["\'](?P<oid>([0-9.]+))["\']\s*'
                )
            elif tag.value == "version":
                self.pattern[tag.value] = _get_special_tag_pattern(
                    name=tag.value, value=r"[0-9\-\:\+T]{24}"
                )
            else:
                self.pattern[tag.value] = _get_special_tag_pattern(
                    name=tag.value, flags=re.MULTILINE
                )


def get_special_tag_pattern(
    name: SpecialScriptTag,
    *,
    value: str = None,
    flags: re.RegexFlag = 0,
    url_type: str = "URL",
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
    # if not value:
    #     return SpecialScriptTagPatterns().pattern[name.value]
    if name.value == "x_ref":
        return re.compile(
            _XREF_TAG_PATTERN.format(
                name=name.value, value=value, type=url_type
            ),
            flags=flags,
        )
    return _get_special_tag_pattern(name=name.value, value=value, flags=flags)


class CommonScriptTagsPattern:
    instance = False

    def __init__(self) -> None:
        self.pattern = _get_tag_pattern(
            name=r"(summary|impact|affected|insight|vuldetect|solution)",
            flags=re.MULTILINE,
        )
        self.instance = self


def get_common_tag_patterns() -> re.Pattern:
    if CommonScriptTagsPattern.instance:
        return CommonScriptTagsPattern.instance.pattern
    return CommonScriptTagsPattern().pattern

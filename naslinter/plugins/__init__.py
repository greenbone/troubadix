# Copyright (C) 2021-2022 Greenbone Networks GmbH
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

from typing import Iterable, List

from naslinter.plugin import Plugin

from .badwords import CheckBadwords
from .copyright_year import CheckCopyrightYear
from .creation_date import CheckCreationDate
from .cve_format import CheckCVEFormat
from .cvss_format import CheckCVSSFormat
from .double_end_points import CheckDoubleEndPoints
from .duplicated_oid import CheckDuplicatedOID
from .duplicated_script_tags import CheckDuplicatedScriptTags
from .newlines import CheckNewlines
from .missing_tag_solution import CheckMissingTagSolution
from .script_category import CheckScriptCategory
from .script_copyright import CheckScriptCopyright
from .update_modification_date import UpdateModificationDate
from .using_display import CheckUsingDisplay
from .valid_oid import CheckValidOID
from .valid_script_tag_names import CheckValidScriptTagNames
from .vt_placement import CheckVTPlacement
from .overlong_script_tags import CheckOverlongScriptTags
from .solution_type import CheckSolutionType
from .todo_tbd import CheckTodoTbd

_PLUGINS = [
    CheckBadwords,
    CheckCopyrightYear,
    CheckCreationDate,
    CheckCVEFormat,
    CheckCVSSFormat,
    CheckDoubleEndPoints,
    CheckDuplicatedOID,
    CheckDuplicatedScriptTags,
    CheckNewlines,
    CheckMissingTagSolution,
    CheckScriptCategory,
    CheckScriptCopyright,
    CheckUsingDisplay,
    CheckValidOID,
    CheckValidScriptTagNames,
    CheckVTPlacement,
    UpdateModificationDate,
    CheckOverlongScriptTags,
    CheckSolutionType,
    CheckTodoTbd,
]


class Plugins:
    def __init__(
        self,
        excluded_plugins: List[str] = None,
        included_plugins: List[str] = None,
    ) -> None:
        self.plugins = _PLUGINS
        if excluded_plugins:
            self.plugins = [
                plugin
                for plugin in _PLUGINS
                if plugin.__name__ not in excluded_plugins
            ]
        if included_plugins:
            self.plugins = [
                plugin
                for plugin in _PLUGINS
                if plugin.__name__ in included_plugins
            ]

    def __iter__(self) -> Iterable[Plugin]:
        return iter(self.plugins)

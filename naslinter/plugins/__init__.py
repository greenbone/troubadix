# Copyright (C) 2021 Greenbone Networks GmbH
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
from .copyright_year import CheckCopyRightYearPlugin
from .update_modification_date import UpdateModificationDate
from .valid_script_tag_names import CheckValidScriptTagNames
from .vt_placement import CheckVTPlacement

_PLUGINS = [
    CheckBadwords,
    CheckCopyRightYearPlugin,
    CheckValidScriptTagNames,
    CheckVTPlacement,
    UpdateModificationDate,
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

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

from typing import Iterable

from naslinter.plugin import Plugin

from .copyright_year import CheckCopyRightYearPlugin
from .valid_script_tag_names import CheckValidScriptTagNames
from .vt_placement import CheckVTPlacement

_PLUGINS = [
    CheckCopyRightYearPlugin,
    CheckValidScriptTagNames,
    CheckVTPlacement,
]


class Plugins:
    def __iter__(self) -> Iterable[Plugin]:
        return iter(_PLUGINS)

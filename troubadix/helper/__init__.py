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

from .helper import (  # noqa: F401
    get_path_from_root,
    get_root,
    is_ignore_file,
    subprocess_cmd,
)
from .patterns import (  # noqa: F401
    ScriptTag,
    SpecialScriptTag,
    get_common_tag_patterns,
    get_script_tag_pattern,
    get_special_script_tag_pattern,
)

# js: can we get this to utf-8 in future @scanner @feed?
CURRENT_ENCODING = "latin1"  # currently default

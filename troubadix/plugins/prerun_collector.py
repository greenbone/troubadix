#  Copyright (c) 2022 Greenbone Networks GmbH
#
#  SPDX-License-Identifier: GPL-3.0-or-later
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
import re

from pathlib import Path
from typing import AnyStr, Iterator, OrderedDict

from troubadix.plugin import LinterError, PreRunPlugin, LinterResult


class CheckPreRunCollector(PreRunPlugin):
    name = "check_prerun_collector"

    @staticmethod
    def run(
        pre_run_data: dict,
    ) -> None:
        """"""
        pre_run_data["pre_run_collector"] = 1

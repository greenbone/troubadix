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

import unittest

from pathlib import Path
from naslinter.plugin import LinterResult
from naslinter.plugins.update_modification_date import UpdateModificationDate


class TestUpdateModificationDate(unittest.TestCase):
    def test_files(self):
        nasl_file = Path(__file__).parent / "test.nasl"

        content = nasl_file.read_text(encoding="latin1")

        # old_datetime = "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)"

        # expected_result = LinterResult(
        #     f"Sucessfully replaced modification date {old_datetime} "
        #     f"with {correctly_formated_datetime}"
        # )

        output = UpdateModificationDate.run(
            nasl_file=nasl_file, file_content=content
        )

        self.assertIsInstance(next(output), LinterResult)

        new_content = nasl_file.read_text(encoding="latin1")
        self.assertNotEqual(content, new_content)

        nasl_file.write_text(content, encoding="latin1")

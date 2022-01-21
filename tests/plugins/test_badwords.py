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

from pathlib import Path
import unittest
from naslinter.plugin import LinterError
from naslinter.plugins.badwords import CheckBadwords


class TestBadwords(unittest.TestCase):
    def test_files(self):
        nasl_file = Path(__file__).parent / "test.nasl"

        lines = nasl_file.read_text().split("\n")

        expected_warning = LinterError(
            f"Badword(s) found in {nasl_file.absolute()}:\n"
            "line    50: openvas is a bad word\n"
            "line    58: OpenVAS is a scanner\n"
        )

        output = CheckBadwords.run(nasl_file=nasl_file, lines=lines)

        self.assertEqual(next(output), expected_warning)

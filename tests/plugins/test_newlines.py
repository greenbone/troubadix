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

from pathlib import Path

from troubadix.plugin import LinterWarning
from troubadix.plugins.newlines import CheckNewlines

from . import PluginTestCase


class CheckNewlinesTestCase(PluginTestCase):
    def test_ok(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = nasl_file.read_text(encoding="latin1")

        results = list(
            CheckNewlines.run(
                nasl_file,
                content.splitlines(),
            )
        )
        self.assertEqual(len(results), 0)

    def test_newline_in_name(self):
        nasl_file = (
            Path(__file__).parent / "test_files" / "fail_name_newline.nasl"
        )
        content = nasl_file.read_text(encoding="latin1")

        results = list(
            CheckNewlines.run(
                nasl_file,
                content.splitlines(),
            )
        )

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterWarning)
        self.assertEqual(
            "Removed a newline within the tag script_name.",
            results[0].message,
        )

        new_content = nasl_file.read_text(encoding="latin1")
        self.assertNotEqual(content, new_content)

        # revert changes for the next time
        nasl_file.write_text(content, encoding="latin1")

    def test_newline_in_name_and_copyright(self):
        nasl_file = (
            Path(__file__).parent
            / "test_files"
            / "fail_name_and_copyright_newline.nasl"
        )
        content = nasl_file.read_text(encoding="latin1")

        results = list(
            CheckNewlines.run(
                nasl_file,
                content.splitlines(),
            )
        )

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], LinterWarning)
        self.assertEqual(
            "Removed a newline within the tag script_name.",
            results[0].message,
        )
        self.assertIsInstance(results[1], LinterWarning)
        self.assertEqual(
            "Removed a newline within the tag script_copyright.",
            results[1].message,
        )

        new_content = nasl_file.read_text(encoding="latin1")
        self.assertNotEqual(content, new_content)

        # revert changes for the next time
        nasl_file.write_text(content, encoding="latin1")

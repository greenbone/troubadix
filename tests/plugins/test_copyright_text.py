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
from unittest.mock import MagicMock

from troubadix.helper import CURRENT_ENCODING
from troubadix.plugin import LinterError
from troubadix.plugins.copyright_text import (
    CORRECT_COPYRIGHT_PHRASE,
    CheckCopyrightText,
)

from . import PluginTestCase

WRONG_TEXTS = [
    "# Text descriptions are largely excerpted from the referenced\n"
    "# advisory, and are Copyright (C) the respective author(s)\n",
    "# Text descriptions are largely excerpted from the referenced\n"
    "# advisory, and are Copyright (C) the respective author(s)\n",
    "# Text descriptions are largely excerpted from the referenced\n"
    "# advisory, and are Copyright (C) the respective author(s)\n",
    "# Some text descriptions might be excerpted from the referenced\n"
    "# advisories, and are Copyright (C) by the respective right holder(s)\n",
]


class CheckCopyrightTextTestCase(PluginTestCase):
    def test_ok(self):
        path = Path("tests/file.nasl")
        content = (
            "# Copyright (C) 2016 Greenbone Networks GmbH\n"
            "# Some text descriptions might be excerpted from (a) referenced\n"
            "# source(s), and are Copyright (C) by the respective "
            "right holder(s).\n"
            'script_copyright("Copyright (C) 1234");'
        )
        fake_context = MagicMock()
        fake_context.nasl_file = path
        fake_context.file_content = content

        plugin = CheckCopyrightText(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_missing_statement(self):
        path = Path("tests/file.nasl")

        content = (
            "# Text descriptions are largely excerpted from the referenced\n"
            "# advisory, and are Copyright (C) the respective author(s)\n"
            '  script_copyright("Copyright (C) 134");'
        )
        fake_context = MagicMock()
        fake_context.nasl_file = path
        fake_context.file_content = content

        expected_content = (
            f"{CORRECT_COPYRIGHT_PHRASE}\n"
            '  script_copyright("Copyright (C) 134");'
        )

        plugin = CheckCopyrightText(fake_context)

        results = list(plugin.run())
        self.assertEqual(len(results), 2)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "The VT is using an incorrect syntax for its copyright "
            "statement. Please start (EXACTLY) with:\n"
            "'script_copyright(\"Copyright (C) followed by the year "
            "(matching the one in creation_date) and the author/company.",
            results[0].message,
        )
        self.assertEqual(
            "The VT was using an incorrect copyright statement. Replaced "
            f"with:\n{CORRECT_COPYRIGHT_PHRASE}",
            results[1].message,
        )
        self.assertEqual(
            path.read_text(encoding=CURRENT_ENCODING), expected_content
        )

        if path.exists():
            path.unlink()

    def test_wrong_copyright_text(self):
        path = Path("tests/file.nasl")

        for wrong_text in WRONG_TEXTS:
            content = (
                "# Copyright (C) 2017 Greenbone Networks GmbH\n"
                f"{wrong_text}"
                '  script_copyright("Copyright (C) 1234");'
            )
            fake_context = MagicMock()
            fake_context.nasl_file = path
            fake_context.file_content = content

            plugin = CheckCopyrightText(fake_context)

            expected_content = (
                "# Copyright (C) 2017 Greenbone Networks GmbH\n"
                f"{CORRECT_COPYRIGHT_PHRASE}\n"
                '  script_copyright("Copyright (C) 1234");'
            )

            results = list(plugin.run())
            self.assertEqual(len(results), 1)

            self.assertIsInstance(results[0], LinterError)
            self.assertEqual(
                "The VT was using an incorrect copyright statement. Replaced "
                f"with:\n{CORRECT_COPYRIGHT_PHRASE}",
                results[0].message,
            )
            self.assertEqual(
                path.read_text(encoding=CURRENT_ENCODING), expected_content
            )

        if path.exists():
            path.unlink()

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
from pathlib import Path

from troubadix.plugin import LinterError
from troubadix.plugins.updated_date_version import CheckUpdatedDateVersion

from . import PluginTestCase


class CheckUpdatedDateVersionTestCase(PluginTestCase):
    def test_nok(self):
        nasl_file = Path(__file__).parent / "test.nasl"
        content = "# not used - this use a subcommand\n"

        results = list(
            CheckUpdatedDateVersion.run(
                nasl_file=nasl_file,
                file_content=content,
            )
        )
        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "Changed VT has a not updated script_version();\n"
            "Please run ./replace_svn_props.py to update both tags.\n",
            results[0].message,
        )
        self.assertEqual(
            "Changed VT has a not updated script_tag("
            'name:"last_modification", ...);\n'
            "Please run ./replace_svn_props.py to update both tags.\n",
            results[1].message,
        )

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
# pylint: disable=protected-access

import unittest
from pathlib import Path

from troubadix.plugin import LinterError, LinterWarning
from troubadix.results import FileResults


class TestResults(unittest.TestCase):
    def test_has_no_results(self):
        fresults = FileResults(file_path=Path("some/file.nasl"))
        fresults.add_plugin_results(plugin_name="test", results=list())

        self.assertFalse(fresults)

    def test_has_results(self):
        fresults = FileResults(file_path=Path("some/file.nasl"))
        fresults.add_plugin_results(
            plugin_name="test",
            results=[
                LinterError("test", file=Path("some/file.nasl"), plugin="test")
            ],
        )

        self.assertTrue(fresults)

    def test_has_results_ok_no_warning(self):
        fresults = FileResults(
            file_path=Path("some/file.nasl"), ignore_warnings=True
        )
        fresults.add_plugin_results(
            plugin_name="test",
            results=[
                LinterWarning(
                    "test", file=Path("some/file.nasl"), plugin="test"
                )
            ],
        )

        self.assertFalse(fresults)

    def test_has_results_no_warning(self):
        fresults = FileResults(
            file_path=Path("some/file.nasl"), ignore_warnings=True
        )
        fresults.add_plugin_results(
            plugin_name="test",
            results=[
                LinterWarning(
                    "test", file=Path("some/file.nasl"), plugin="test"
                )
            ],
        )
        fresults.add_plugin_results(
            plugin_name="test",
            results=[
                LinterError("test", file=Path("some/file.nasl"), plugin="test")
            ],
        )

        self.assertTrue(fresults)

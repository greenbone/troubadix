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

""" updating the modification time in VTs that have been touched/edited """

import datetime
import re

from typing import Iterator
from troubadix.helper import CURRENT_ENCODING

from troubadix.plugin import LinterError, LinterResult, FilePlugin


class UpdateModificationDate(FilePlugin):
    name = "update_modification_date"

    def run(self) -> Iterator[LinterResult]:
        # update modification date
        file_content = self.context.file_content

        tag_template = 'script_tag(name:"last_modification", value:"{date}");'
        mod_pattern = (
            r"script_tag\(name:\"last_modification\", value:\"(.*)\"\);"
        )

        match = re.search(
            pattern=mod_pattern,
            string=file_content,
        )
        if not match:
            yield LinterError(
                "VT does not contain a modification day script tag."
            )
            return

        old_datetime = match.groups()[0]

        now = datetime.datetime.now(datetime.timezone.utc)
        # get that date formatted correctly:
        # "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)"
        correctly_formated_datetime = (
            f"{now:%Y-%m-%d %H:%M:%S %z (%a, %d %b %Y)}"
        )

        file_content = file_content.replace(
            tag_template.format(date=old_datetime),
            tag_template.format(date=correctly_formated_datetime),
        )

        # update script version
        version_template = 'script_version("{date}");'
        vers_template = r"script_version\(\"(.*)\"\);"

        match = re.search(
            pattern=vers_template,
            string=file_content,
        )
        if not match:
            yield LinterError("VT does not contain a script version.")
            return

        old_version = match.groups()[0]
        # get that date formatted correctly:
        # "2021-03-24T10:08:26+0000"
        correctly_formated_version = f"{now:%Y-%m-%dT%H:%M:%S%z}"

        file_content = file_content.replace(
            version_template.format(date=old_version),
            version_template.format(date=correctly_formated_version),
        )
        self.context.nasl_file.write_text(
            file_content, encoding=CURRENT_ENCODING
        )

        yield LinterResult(
            f"Replaced modification_date {old_datetime} "
            f"with {correctly_formated_datetime} and script_version "
            f"{old_version} with {correctly_formated_version}."
        )

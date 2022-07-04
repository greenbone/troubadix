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
from typing import Iterator

from troubadix.helper import (
    CURRENT_ENCODING,
    SpecialScriptTag,
    get_path_from_root,
    get_special_script_tag_pattern,
)
from troubadix.plugin import FilesPlugin, LinterError, LinterResult

# import json

OPENVAS_OID_PREFIX = r"1.3.6.1.4.1.25623.1.[0-9]+."
OID_RE = re.compile(r"^1\.3\.6\.1\.4\.1\.25623\.1\.[0-9]+\.[\d.]+$")

KNOWN_DUPS = {"1.3.6.1.4.1.25623.1.0.850001", "1.3.6.1.4.1.25623.1.0.95888"}
KNOWN_ABSENTS = {"template.nasl"}


class CheckDuplicateOID(FilesPlugin):
    name = "check_duplicate_oid"

    def run(self) -> Iterator[LinterResult]:
        """Run PRE_RUN_COLLECTOR."""

        mapping = dict()

        for nasl_file in self.context.nasl_files:
            if not nasl_file.suffix == ".nasl":
                continue

            nasl_file_root = get_path_from_root(nasl_file, self.context.root)

            oid = None
            content = nasl_file.read_text(encoding=CURRENT_ENCODING)
            match = get_special_script_tag_pattern(SpecialScriptTag.OID).search(
                content
            )

            if match:
                oid = match.group("oid")

            if not oid:
                yield LinterError(
                    f"Could not find an OID in '{nasl_file_root}'.",
                    plugin=self.name,
                    file=nasl_file,
                )

            elif not OID_RE.match(oid):
                yield LinterError(
                    f"Invalid OID {oid} found in '{nasl_file_root}'.",
                    plugin=self.name,
                    file=nasl_file,
                )

            elif oid not in mapping:
                mapping[oid] = nasl_file_root
            else:
                yield LinterError(
                    f"OID {oid} already used by '{mapping[oid]}'",
                    file=nasl_file,
                    plugin=self.name,
                )

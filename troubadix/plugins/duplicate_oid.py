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
    get_special_script_tag_pattern,
    get_path_from_root,
)
from troubadix.plugin import (
    FilesPlugin,
    LinterError,
    LinterResult,
)

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
        duplicates = []
        absents = []
        invalids = []

        for nasl_file in self.context.nasl_files:
            if not nasl_file.suffix == ".nasl":
                continue

            oid = None
            file_name = get_path_from_root(nasl_file, self.context.root)
            content = nasl_file.read_text(encoding=CURRENT_ENCODING)
            # search for deprecated script_id
            match = get_special_script_tag_pattern(SpecialScriptTag.OID).search(
                content
            )

            if match:
                oid = match.group("oid")
            else:
                match = get_special_script_tag_pattern(
                    SpecialScriptTag.ID
                ).search(content)
                if match:
                    oid = OPENVAS_OID_PREFIX + match.group("oid")

            if not oid:
                absents.append(file_name)
                yield LinterError(f"{file_name}: Could not find an OID.")

            elif not OID_RE.match(oid):
                invalids.append(file_name)
                yield LinterError(f"{file_name}: Invalid OID {oid} found.")

            elif oid not in mapping:
                mapping[oid] = str(file_name)
            else:
                duplicates.append(
                    {
                        "oid": oid,
                        "duplicate": file_name,
                        "first_usage": mapping[oid],
                    }
                )

                yield LinterError(
                    f"{file_name}: OID {oid} already "
                    f"used by '{mapping[oid]}'"
                )

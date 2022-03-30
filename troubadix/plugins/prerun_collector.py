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
from typing import Iterator, List

from troubadix.helper import (
    SpecialScriptTag,
    get_special_script_tag_pattern,
    get_path_from_root,
)
from troubadix.plugin import (
    LinterError,
    # LinterMessage,
    LinterResult,
    PreRunPlugin,
)

OPENVAS_OID_PREFIX = r"1.3.6.1.4.1.25623.1.[0-9]+."
OID_RE = re.compile(r"^1\.3\.6\.1\.4\.1\.25623\.1\.[0-9]+\.[\d.]+$")

KNOWN_DUPS = {"1.3.6.1.4.1.25623.1.0.850001", "1.3.6.1.4.1.25623.1.0.95888"}
KNOWN_ABSENTS = {"template.nasl"}


class CheckPreRunCollector(PreRunPlugin):
    name = "check_prerun_collector"

    @staticmethod
    def run(
        pre_run_data: dict,
        nasl_files: List[Path],
    ) -> Iterator[LinterResult]:
        """Run PRE_RUN_COLLECTOR."""

        mapping = dict()
        duplicates = []
        absents = []
        invalids = []

        for nasl_file in nasl_files:
            if nasl_file.suffix == ".nasl":
                oid = None
                file_name = get_path_from_root(nasl_file)
                content = nasl_file.read_text(encoding="latin-1")
                # search for deprecated script_id
                match = get_special_script_tag_pattern(
                    SpecialScriptTag.OID
                ).search(content)
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
                    yield LinterError(f"{file_name}: Could not find a OID.")
                elif not OID_RE.match(oid):
                    invalids.append(file_name)
                    yield LinterError(f"{file_name}: Invalid OID {oid} found.")
                elif oid not in mapping:
                    mapping[oid] = file_name
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
                # yield LinterMessage(f"{file_name}: OK!")

                # builder = OIDDictBuilder()
                # builder.scan(nasl_files)

        # pre_run_data["oid_mappings"] = builder.dict_mapping()


class OIDDictBuilder:
    def __init__(self):
        self.mapping = dict()
        self.duplicates = []
        self.absents = []
        self.invalids = []

    def scan(self, files: List[Path]) -> None:
        for nasl_file in files:
            if nasl_file.suffix == ".nasl":
                self._find_oid(nasl_file=nasl_file)

    def _find_oid(self, nasl_file: Path) -> None:
        file_name = str(nasl_file).split("nasl/", maxsplit=1)[-1]
        content = nasl_file.read_text(encoding="latin-1")
        # search for deprecated script_id
        match = get_special_script_tag_pattern(SpecialScriptTag.OID).search(
            content
        )
        if match:
            oid = OPENVAS_OID_PREFIX + match.group("oid")
        else:
            match = get_special_script_tag_pattern(SpecialScriptTag.ID).search(
                content
            )
            if match:
                oid = match.group("oid")
        if not oid:
            self.absents.append(file_name)
            yield LinterError(f"{file_name}: Could not find a OID.")
        elif not OID_RE.match(oid):
            self.invalids.append(file_name)
            yield LinterError(f"{file_name}: Invalid OID {oid} found.")
        elif oid not in self.mapping:
            self.mapping[oid] = file_name
        else:
            self.duplicates.append(
                {
                    "oid": oid,
                    "duplicate": file_name,
                    "first_usage": self.mapping[oid],
                }
            )
            yield LinterError(
                f"{file_name}: OID {oid} already used by '{self.mapping[oid]}'"
            )
        yield LinterError("TEST")

    def dict_mapping(self) -> dict:
        return dict(
            {
                "mapping": self.mapping,
                "duplicates": self.duplicates,
                "absents": self.absents,
                "invalids": self.invalids,
            }
        )

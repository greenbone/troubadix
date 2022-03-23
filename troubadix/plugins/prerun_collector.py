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
import errno
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import List

from troubadix.helper import get_root, SpecialScriptTag, get_special_tag_pattern
from troubadix.plugin import PreRunPlugin

OPENVAS_OID_PREFIX = r"1.3.6.1.4.1.25623.1.[0-9]+."
OID_RE = re.compile(r"^" + OPENVAS_OID_PREFIX.replace(".", r"\.") + r"[\d.]+$")

KNOWN_DUPS = {"1.3.6.1.4.1.25623.1.0.850001", "1.3.6.1.4.1.25623.1.0.95888"}
KNOWN_ABSENTS = {"template.nasl"}


class CheckPreRunCollector(PreRunPlugin):
    name = "check_prerun_collector"

    @staticmethod
    def run(
        pre_run_data: dict,
        nasl_files: List[Path],
        **kwargs,
    ) -> None:
        """Run PRE_RUN_COLLECTOR."""

        builder = OIDMapBuilder(True, **kwargs)
        builder.scan(nasl_files)
        # oidmappingfile = Path(os.environ.get("QATMPDIR", "")) /
        # "oidmapping.txt"
        # builder.write_mapping(oidmappingfile)
        pre_run_data["oid_mappings"] = builder.dict_mapping()


class OIDMapBuilder:
    def __init__(self, verbose, **kwargs):
        self.mapping = dict()
        self.verbose = verbose
        self.duplicates = []
        self.absents = []
        self.invalids = []
        self.args = kwargs

    def scan(self, files: List[Path]):
        for file in files:
            if file.suffix == ".nasl":
                self.scan_file(file)

    def scan_file(self, fullname):
        # the filename in the mapping file must be relative to nvt basedir
        root = get_root(fullname)
        assert str(fullname).startswith(str(root))
        filename = str(fullname)[len(str(root)) :].lstrip("/")

        with fullname.open(encoding="latin-1") as f:
            lines = f.readlines()
        for line in lines:
            line = line.strip()
            if line.startswith("#"):
                # skip comments
                continue
            oid = self.find_oid(line)
            if oid is not None:
                if OID_RE.match(oid) is None:
                    self.invalids.append(filename)
                    if self.verbose:
                        print(
                            f"Invalid OID {oid} used for {filename}",
                            file=sys.stderr,
                        )
                    break
                if oid not in self.mapping:
                    self.mapping[oid] = filename
                else:
                    self.duplicates.append(
                        {
                            "oid": oid,
                            "duplicate": filename,
                            "first_usage": self.mapping[oid],
                        }
                    )
                    if self.verbose:
                        print(
                            f"OID {oid} used by both '{filename}' and "
                            f"'{self.mapping[oid]}'",
                            file=sys.stderr,
                        )
                break
        else:
            self.absents.append(filename)
            if self.verbose:
                print(
                    f"Could not find script_id in {filename}", file=sys.stderr
                )

    def find_oid(self, line):
        # search for deprecated script_id in line

        match = self.args["special_tag_pattern"][
            SpecialScriptTag.ID.value
        ].search(line)
        if match:
            return OPENVAS_OID_PREFIX + match.group("id")
        match = get_special_tag_pattern(
            name=SpecialScriptTag.OID,
            value=r'\s*(?P<quote>[\'"])(?P<oid>([0-9.]+))(?P=quote)\s*',
            flags=re.IGNORECASE,
        ).search(line)
        if match:
            return match.group("oid")
        return None

    def dict_mapping(self) -> dict:
        return dict(
            {
                "mapping": self.mapping,
                "duplicates": self.duplicates,
                "absents": self.absents,
                "invalids": self.invalids,
            }
        )

    def write_mapping(self, filename: Path):
        """Writes the mapping to the file named by filename"""
        directory = filename.parent.resolve()
        fileno, tempname = tempfile.mkstemp(".txt", "oidmapping", directory)
        try:
            outfile = os.fdopen(fileno, "w")
            for key, value in self.mapping.items():
                outfile.write(f"{key} {value}\n")
            outfile.flush()
            os.rename(tempname, filename)
            outfile.close()
        finally:
            try:
                os.remove(tempname)
            except OSError as exc:
                if exc.errno == errno.ENOENT:
                    # should only happen if tempname has already been
                    # renamed and therefore doesn't exist any more under that
                    # name
                    pass
                else:
                    raise exc

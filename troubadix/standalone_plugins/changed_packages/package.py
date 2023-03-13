# Copyright (C) 2023 Greenbone AG
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


from argparse import ArgumentError
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict


class Direction(Enum):
    ACTIVE = 1
    PASSIVE = 2


class Reasons(str, Enum):
    DROPPED_ARCHITECTURE = "Dropped architecture"
    ADDED_EPOCH = "Added epoch"
    CHANGED_UPDATE = "Changed update"
    ADDED_UDEB = "Added udeb package"
    ADDED_RELEASE = "Added a new release"

    def __str__(self) -> str:
        return self.name.lower().replace("_", "-")

    @classmethod
    def from_cli_argument(cls, cli_argument: str):
        try:
            return cls[cli_argument.upper().replace("-", "_")]
        except KeyError as error:
            raise ArgumentError(
                None, f"Invalid reason '{cli_argument}'"
            ) from error


@dataclass()
class Package:
    name: str
    version: str
    release: str
    reasons: Dict[Reasons, Direction] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash((self.name, self.version, self.release))

    def __eq__(self, other: "Package") -> bool:
        return (
            self.name == other.name
            and self.version == other.version
            and self.release == other.release
            and self.reasons == other.reasons
        )

    def __lt__(self, other: "Package") -> bool:
        # Sort by release first, then the other fields
        if self.release != other.release:
            return self.release < other.release
        if self.name != other.name:
            return self.name < other.name
        if self.version != other.version:
            return self.version < other.version

        return False

    def __str__(self) -> str:
        result = f"{self.name : <50} {self.version : <40} {self.release : <10}"

        reasons = ", ".join(
            f"{change}"
            f"{' in new package' if direction == Direction.PASSIVE else ''}"
            for change, direction in self.reasons.items()
        )
        result += f"{reasons : <10}"

        return result

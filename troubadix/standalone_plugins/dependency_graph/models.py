# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

from dataclasses import dataclass, field
from enum import Enum


class Feed(str, Enum):
    COMMON = "common"
    FEED_21_04 = "21.04"
    FEED_22_04 = "22.04"


class OutputLevel(Enum):
    ERROR = 1
    WARNING = 2
    INFO = 3


@dataclass
class Dependency:
    name: str
    # Indicates whether the dependency will only run if an enterprise feed is used.
    # Controlled by a specific if check. Does not indicate the script's feed.
    is_enterprise_feed: bool


@dataclass
class Script:
    name: str
    feed: str
    dependencies: list[Dependency]
    category: int
    deprecated: bool


@dataclass
class Result:
    """Holds the results of a single check.
    A check can report a combination of errors, warnings and infos
    """

    name: str
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    infos: list[str] = field(default_factory=list)

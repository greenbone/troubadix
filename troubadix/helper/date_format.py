# Copyright (C) 2025 Greenbone AG
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import datetime
from typing import Iterator

from troubadix.plugin import LinterError, LinterResult


def check_date(
    date: str, date_name: str, file: str, plugin: str
) -> Iterator[LinterResult]:
    """
    Checks if a given date string is correctly formatted.
    Example: "2017-11-29 13:56:41 +0100 (Wed, 29 Nov 2017)"
    """

    if not date:
        yield LinterError(
            "No creation date has been found.",
            file=file,
            plugin=plugin,
        )
        return

    try:
        # 2017-11-29 13:56:41 +0100
        date_left = datetime.strptime(date[:25], "%Y-%m-%d %H:%M:%S %z")

        # Wed, 29 Nov 2017
        date_right = datetime.strptime(date[27:43], "%a, %d %b %Y")

        week_day_parsed = date_right.strftime("%a")

    except ValueError:
        yield LinterError(
            f"Missing or incorrectly formatted {date_name}.",
            file=file,
            plugin=plugin,
        )
        return

    # Wed
    week_day_str = date[27:30]

    if date_left.date() != date_right.date():
        yield LinterError(
            f"The {date_name} consists of two different dates.",
            file=file,
            plugin=plugin,
        )

    # Check correct weekday
    elif week_day_str != week_day_parsed:
        formatted_date = week_day_parsed
        yield LinterError(
            f"Wrong day of week. Please change it from '{week_day_str}"
            f"' to '{formatted_date}'.",
            file=file,
            plugin=plugin,
        )

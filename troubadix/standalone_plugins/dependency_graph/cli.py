# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG


import logging
import os
from argparse import ArgumentError, ArgumentParser, ArgumentTypeError, Namespace
from pathlib import Path

from troubadix.argparser import directory_type_existing

from .models import Feed


def feed_type(value: str) -> Feed:
    try:
        return Feed[value.upper()]
    except KeyError:
        raise ArgumentTypeError(f"Invalid Feed value: '{value}'")


def parse_args() -> Namespace:
    parser = ArgumentParser(
        description="Tool for analysing the dependencies in the NASL repository.",
    )
    parser.add_argument(
        "root",
        type=directory_type_existing,
        default=os.environ.get("VTDIR"),
        help="directory that should be linted",
    )
    parser.add_argument(
        "-f",
        "--feed",
        type=feed_type,
        choices=Feed,
        nargs="+",
        default=[Feed.FULL],
        help="feed",
    )
    parser.add_argument(
        "--log",
        default="WARNING",
        help="Set the logging level (INFO, WARNING, ERROR)",
    )
    parser.add_argument("-v", "--verbose", action="count", default=0)

    args = parser.parse_args()

    if not args.root:
        vtdir = os.environ.get("VTDIR")
        if not vtdir:
            raise ArgumentError(
                "The environment variable 'VTDIR' is not set, and no path was provided."
            )
        args.root = Path(vtdir)
        logging.info(f"using root {vtdir} from 'VTDIR'")

    return args

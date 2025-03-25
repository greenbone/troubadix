# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG


import os
from argparse import ArgumentParser, Namespace
from pathlib import Path

from troubadix.argparser import directory_type_existing

from .models import Feed


def parse_args() -> Namespace:
    parser = ArgumentParser(
        description="Tool for analysing the dependencies in the NASL repository.",
    )
    parser.add_argument(
        "-r",
        "--root",
        type=directory_type_existing,
        help="root for nasl directory that should be linted, uses $VTDIR if no path is given",
    )
    parser.add_argument(
        "-f",
        "--feed",
        type=Feed,
        choices=Feed,
        default=Feed.COMMON,
        help="Feed selection",
    )
    parser.add_argument(
        "--log",
        type=str.upper,
        default="WARNING",
        choices=["INFO", "WARNING", "ERROR"],
        help="Set the logging level (default: WARNING)",
    )

    args = parser.parse_args()

    if not args.root:
        vtdir = os.environ.get("VTDIR")
        if not vtdir:
            raise ValueError(
                "The environment variable 'VTDIR' is not set,"
                " and no root path with '--root' was provided."
            )
        args.root = Path(vtdir)

    return args

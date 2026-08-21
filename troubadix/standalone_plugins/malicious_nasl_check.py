# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG

import argparse
import logging
import re
import sys
from pathlib import Path

WHITELISTED_FILES = [
    "host_details",
    "pkg-lib-deb",
    "pkg-lib-rpm",
    "pkg-lib-slack",
    "revisions-lib",
    "version_func",
]
WHITELISTED_COMMANDS = [
    "script_tag",
    "script_version",
    "script_xref",
    "get_app_full",
    "get_app_port",
    "get_app_version",
    "isdpkgvuln",
    "isrpmvuln",
    "isslkpkgvuln",
    "security_message",
    "security_message",
    "version_in_range_exclusive",
    "version_in_range",
    "version_is_less_equal",
    "version_is_less",
    "report_fixed_ver",
    "get_app_version_and_location",
    "dpkg_get_ssh_release",
    "rpm_get_ssh_release",
    "slk_get_ssh_release",
]
logger = logging.getLogger(__name__)

DEFAULT_VTS_DIR = Path("vts")

INCLUDE_PATTERN = re.compile(r'include\("(?P<include_name>[a-zA-Z0-9_-]+)\.inc"\);')

# matches words (with boundary) before a `(` with an arg and then a `:`
COMMANDS_PATTERN = re.compile(r"\b(?P<method>[A-Za-z_][A-Za-z0-9_]*)\([A-Za-z_]*:")


def parse_arguments():
    parser = argparse.ArgumentParser("Check for unexpected files or commands in NASL scripts.")

    parser.add_argument(
        "-d", "--vt-dir", default=Path("vts"), type=Path, help="Root location of the VTS repository"
    )

    return parser.parse_args()


def parse_vts(vt_dir: Path) -> list[Path]:
    files_with_errors = []

    for vt in vt_dir.rglob("*.nasl"):
        content = vt.read_text(encoding="LATIN-1")

        for match in INCLUDE_PATTERN.finditer(content):
            include_name = match.group("include_name")
            if include_name not in WHITELISTED_FILES:
                files_with_errors.append((vt, include_name))

        for match in COMMANDS_PATTERN.finditer(content):
            method = match.group("method")
            if method not in WHITELISTED_COMMANDS:
                files_with_errors.append((vt, method))

    return files_with_errors


def main():
    arguments = parse_arguments()
    errors = parse_vts(arguments.vt_dir)

    if errors:
        print(f"{len(errors)} file(s) with unexpected NASL methods found:")
        for file in errors:
            print(file)
        return 1
    else:
        return 0


if __name__ == "__main__":
    sys.exit(main())

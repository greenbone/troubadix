# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG

import os
import re
import sys
from argparse import ArgumentParser, Namespace
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from troubadix.argparser import file_type
from troubadix.helper.patterns import (
    get_special_script_tag_pattern,
    get_script_tag_pattern,
    ScriptTag,
    SpecialScriptTag,
)


class PathException(Exception):
    pass


@dataclass
class DeprecatedFile:
    name: str
    full_path: Path
    content: str


# CHANGE AS NEEDED
FILENAME_REGEX = re.compile(r"gb_")

KB_ITEMS = re.compile(r"set_kb_item\(.+\);")


def update_summary(file: DeprecatedFile, oid_mapping_path: Path = None) -> str:
    """Update the summary of the nasl script by adding the information
    that the script has been deprecated, and if possible, the oid of
    the new notus script replacing it.

    Args:
        file: DeprecatedFile object containing the content of the VT
        oid_mapping_path (optional): The path to the file that contains a
            mapping of old oids to new oids (see notus-generator transition
            layer)

    Returns:
        The updated content of the file
    """
    if oid_mapping_path:
        oid = match_oid(file.content, oid_mapping_path)
        deprecate_text = f"This VT has been replaced by the new VT: {oid}. "
    else:
        deprecate_text = "This VT has been deprecated."

    old_summary = get_summary(file.content)
    if old_summary:
        new_summary = deprecate_text + old_summary
        file.content = file.content.replace(old_summary, new_summary)
    else:
        print(f"No summary in: {file.name}")

    return file.content


def match_oid(content: str, oid_mapping_path: Path) -> str:
    """Find the new Notus oid that has been mapped to the old
    OID, so we can add this to the deprecation note.
    """
    pattern = get_special_script_tag_pattern(SpecialScriptTag.OID)
    match = re.search(pattern, content)
    old_oid = match.group(1)

    # needs improvement
    # pylint: disable=import-error, import-outside-toplevel
    sys.path.append(oid_mapping_path)
    from redhat import mapping

    reverse_mapping = dict((v, k) for k, v in mapping.items())
    new_oid = reverse_mapping.get(old_oid)
    return new_oid


def finalize_content(content: str) -> str:
    """Update the content field of the nasl script by adding the
    deprecated tag and removing the extra content."""
    content_to_keep = content.split("exit(0);")[0]
    return content_to_keep + (
        "script_tag(name: 'deprecated', value: TRUE);"
        "\n\nexit(0);\n}\n\nexit(66);\n"
    )


def get_files(dir_path: Path = None, file: Path = None) -> list[DeprecatedFile]:
    """Create a list of DeprecatedFile objects

    Args:
        dir_path (optional): The path to the directory with the files to
            be deprecated
        file (optional): The path to the single file to be deprecated.

    Returns:
        List of DeprecatedFile objects
    """
    to_deprecate = []
    if file and re.match(FILENAME_REGEX, file.name):
        to_deprecate.append(
            DeprecatedFile(
                file.name,
                file.absolute(),
                file.open("r", encoding="latin-1").read(),
            )
        )
    else:
        valid_files = [
            file
            for file in dir_path.glob("**/*")
            if re.match(FILENAME_REGEX, file.name)
        ]
        for file in valid_files:
            to_deprecate.append(
                DeprecatedFile(
                    file.name,
                    file.absolute(),
                    file.open("r", encoding="latin-1").read(),
                )
            )
    return to_deprecate


def get_summary(content: str) -> Optional[str]:
    """Extract the summary from the nasl script"""
    pattern = get_script_tag_pattern(ScriptTag.SUMMARY)
    if match_summary := re.search(pattern, content):
        value = match_summary.group().split('value:"')[1]
        return value.replace('");', "")
    return None


def deprecate(
    output_path: Path,
    to_deprecate: list[DeprecatedFile],
    oid_mapping_path: Path = None,
) -> None:
    """Deprecate the selected VTs by removing unnecessary keys, updating the
    summary, and adding the deprecated tag.

    Args:
        output_path: the directory where the deprecated VTs should be written
            to, i.e. "attic"
        to_deprecate: the list of files to be deprecated
        oid_mapping_path (optional) : the path to the file where the old
            oids have been mapped to the new oids (see "transition_layer"
            in notus-generator).
    """
    output_path.mkdir(parents=True, exist_ok=True)
    for file in to_deprecate:
        items = re.findall(KB_ITEMS, file.content)
        if items:
            print(
                f"Unable to deprecate {file.name}. There are still KB keys "
                f"remaining."
            )
            continue
        file.content = update_summary(file, oid_mapping_path)
        file.content = finalize_content(file.content)

        # Drop any unnecessary script tags like script_dependencies(),
        # script_require_udp_ports() or script_mandatory_keys()
        tags_to_remove = list()
        dependencies = re.search(
            get_special_script_tag_pattern(SpecialScriptTag.DEPENDENCIES),
            file.content,
        )
        if dependencies:
            tags_to_remove.append(dependencies.group())

        udp = re.search(
            get_special_script_tag_pattern(SpecialScriptTag.REQUIRE_UDP_PORTS),
            file.content,
        )
        if udp:
            tags_to_remove.append(udp.group())

        man_keys = re.search(
            get_special_script_tag_pattern(SpecialScriptTag.MANDATORY_KEYS),
            file.content,
        )
        if man_keys:
            tags_to_remove.append(man_keys.group())

        for tag in tags_to_remove:
            file.content = file.content.replace("  " + tag + "\n", "")

        os.rename(file.full_path, output_path / file.name)

        with open(output_path / file.name, "w", encoding="latin-1") as f:
            f.write(file.content)
            f.truncate()


def parse_args(args: Iterable[str] = None) -> Namespace:
    parser = ArgumentParser(description="Deprecate VTs")
    parser.add_argument(
        "-o",
        "--output-path",
        metavar="<output_path>",
        type=str,
        required=True,
        help="Path where the deprecated files should be written to.",
    )
    parser.add_argument(
        "-f",
        "--file",
        metavar="<file>",
        nargs="?",
        default=None,
        type=file_type,
        help="single file to deprecate",
    )
    parser.add_argument(
        "-i",
        "--input-path",
        metavar="<input_path>",
        nargs="?",
        default=None,
        type=str,
        help="Path to the existing nasl scripts",
    )
    parser.add_argument(
        "-m",
        "--oid-mapping-path",
        metavar="<oid_mapping_path>",
        nargs="?",
        default=None,
        type=str,
        help="Path to the oid mapping file",
    )
    return parser.parse_args(args)


def main():
    args = parse_args()
    output_path = Path(args.output_path)
    input_path = Path(args.input_path) if args.input_path else None
    oid_mapping_path = args.oid_mapping_path if args.oid_mapping_path else None
    single_file = Path(args.file) if args.file else None

    if not input_path and not single_file:
        raise PathException(
            "Please provide either the path to a single file or a directory."
        )

    if not input_path.is_dir():
        raise PathException("Input path is not a directory.")

    to_deprecate = get_files(input_path, single_file)

    deprecate(output_path, to_deprecate, oid_mapping_path)


if __name__ == "__main__":
    main()

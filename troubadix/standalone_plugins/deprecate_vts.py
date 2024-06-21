# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG

import os
import re
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


KB_ITEMS = re.compile(r"set_kb_item\(.+\);")


def update_summary(file: DeprecatedFile, deprecation_reason: str) -> str:
    """Update the summary of the nasl script by adding the information
    that the script has been deprecated, and if possible, the oid of
    the new notus script replacing it.

    Args:
        file: DeprecatedFile object containing the content of the VT
        deprecation_reason: The reason this VT is being deprecated,
            from a list of options.

    Returns:
        The updated content of the file
    """
    deprecate_text = "Note: This VT has been deprecated "
    if deprecation_reason == "notus":
        deprecate_text += "and replaced by a Notus scanner based one."
    if deprecation_reason == "merged":
        deprecate_text = "because it has been merged into a different VT."
    if deprecation_reason == "defunct":
        deprecate_text = "and is therefore no longer functional."
    if deprecation_reason == "duplicate":
        deprecate_text = "as a duplicate."

    old_summary = get_summary(file.content)
    if old_summary:
        new_summary = old_summary + "\n" + deprecate_text
        file.content = file.content.replace(old_summary, new_summary)
    else:
        print(f"No summary in: {file.name}")

    return file.content


def finalize_content(content: str) -> str:
    """Update the content field of the nasl script by adding the
    deprecated tag and removing the extra content."""
    content_to_keep = content.split("exit(0);")[0]
    return content_to_keep + (
        'script_tag(name:"deprecated", value:TRUE);'
        "\n\nexit(0);\n}\n\nexit(66);\n"
    )


def get_files(
    dir_path: Path = None, file: Path = None, filename_prefix=None
) -> list[DeprecatedFile]:
    """Create a list of DeprecatedFile objects

    Args:
        dir_path (optional): The path to the directory with the files to
            be deprecated
        file (optional): The path to the single file to be deprecated.
        filename_prefix(optional): A filename prefix, such as 'gb_rhsa_2021',
            can be used to only deprecate certain VTs

    Returns:
        List of DeprecatedFile objects
    """
    to_deprecate = []
    filename_filter = re.compile(rf"{filename_prefix}")
    if filename_prefix:
        if file and re.match(filename_filter, file.name):
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
                if re.match(filename_filter, file.name)
            ]
            for file in valid_files:
                to_deprecate.append(
                    DeprecatedFile(
                        file.name,
                        file.absolute(),
                        file.open("r", encoding="latin-1").read(),
                    )
                )
    else:
        if file:
            to_deprecate.append(
                DeprecatedFile(
                    file.name,
                    file.absolute(),
                    file.open("r", encoding="latin-1").read(),
                )
            )
        else:
            for file in dir_path.glob("**/*"):
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
    deprecation_reason: str,
) -> None:
    """Deprecate the selected VTs by removing unnecessary keys, updating the
    summary, and adding the deprecated tag.

    Args:
        output_path: the directory where the deprecated VTs should be written
            to, i.e. "attic"
        to_deprecate: the list of files to be deprecated
        deprecation_reason: The reason this VT is being deprecated,
        from a list of options.
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
        file.content = update_summary(file, deprecation_reason)
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
        help="Single file to deprecate",
    )
    parser.add_argument(
        "-i",
        "--input-path",
        metavar="<input_path>",
        nargs="?",
        default=None,
        type=str,
        help="Path to the existing nasl script directory",
    )
    parser.add_argument(
        "-p",
        "--filename-prefix",
        metavar="<filename_prefix>",
        nargs="?",
        default=None,
        type=str,
        help="The prefix of the files you would like to deprecate,"
        "for example 'gb_rhsa_2021' to filter on the year",
    )
    parser.add_argument(
        "-d",
        "--deprecation-reason",
        metavar="<deprecation_reason>",
        choices=["notus", "merged", "duplicate", "defunct"],
        type=str,
        help="The reason the VT is being deprecated. Options are 'notus':"
        "The VT has been replaced by a new Notus VT. 'Merged': the VT has"
        "been merged with another still active VT, 'duplicate': The VT has"
        "a still active duplicate, 'defunct': The VT is no longer "
        "functional.",
    )
    return parser.parse_args(args)


def main():
    args = parse_args()
    output_path = Path(args.output_path)
    input_path = Path(args.input_path) if args.input_path else None
    single_file = Path(args.file) if args.file else None
    deprecation_reason = args.deprecation_reason
    filename_prefix = args.filename_prefix if args.filename_prefix else None

    if not input_path and not single_file:
        raise PathException(
            "Please provide either the path to a single file or a directory."
        )

    if not input_path.is_dir():
        raise PathException("Input path is not a directory.")

    to_deprecate = get_files(input_path, single_file, filename_prefix)

    deprecate(output_path, to_deprecate, deprecation_reason)


if __name__ == "__main__":
    main()

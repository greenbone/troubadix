# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG

import re
from argparse import ArgumentParser, Namespace
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional

from troubadix.argparser import file_type, directory_type
from troubadix.helper.patterns import (
    get_special_script_tag_pattern,
    get_script_tag_pattern,
    ScriptTag,
    SpecialScriptTag,
)


class Deprecations(Enum):
    NOTUS = "and replaced by a Notus scanner based one."
    MERGED = "because it has been merged into a different VT."
    DEFUNCT = "and is therefore no longer functional."
    DUPLICATE = "as a duplicate."


@dataclass
class DeprecatedFile:
    name: str
    full_path: Path
    content: str


KB_ITEMS_PATTERN = re.compile(r"set_kb_item\(.+\);")


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
    old_summary = _get_summary(file.content)
    if not old_summary:
        print(f"No summary in: {file.name}")
        return file.content

    deprecate_text = (
        f"Note: This VT has been deprecated "
        f"{Deprecations[deprecation_reason].value}"
    )

    new_summary = old_summary + "\n" + deprecate_text
    file.content = file.content.replace(old_summary, new_summary)

    return file.content


def _finalize_content(content: str) -> str:
    """Update the content field of the nasl script by adding the
    deprecated tag and removing the extra content."""
    content_to_keep = content.split("exit(0);")[0]
    return content_to_keep + (
        'script_tag(name:"deprecated", value:TRUE);'
        "\n\nexit(0);\n}\n\nexit(66);\n"
    )


def get_files_from_path(dir_path: Path = None) -> list:
    """Get a list of files from the input path provided

    Args:
        dir_path (optional): The path to the directory with the files to
            be deprecated
    """
    return [file for file in dir_path.glob("**/*")]


def filter_files(
    files: list, filename_prefix: str = None
) -> list[DeprecatedFile]:
    """Filter the files based on a provided prefix and convert them into
    DeprecatedFile objects

    Args:
        files: a list of files to deprecate, should be .nasl VTs
        filename_prefix: an optional prefix to filter only specific files

    Returns:
        List of DeprecatedFile objects

    """
    to_deprecate = []
    if filename_prefix:
        filename_filter = re.compile(rf"{filename_prefix}")
        files[:] = [
            file for file in files if re.match(filename_filter, file.name)
        ]

    for file in files:
        with file.open("r", encoding="latin-1") as fh:
            to_deprecate.append(
                DeprecatedFile(
                    file.name,
                    file.absolute(),
                    fh.read(),
                )
            )
    return to_deprecate


def _get_summary(content: str) -> Optional[str]:
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
        if re.findall(KB_ITEMS_PATTERN, file.content):
            print(
                f"Unable to deprecate {file.name}. There are still KB keys "
                f"remaining."
            )
            continue
        file.content = update_summary(file, deprecation_reason)
        file.content = _finalize_content(file.content)

        # Drop any unnecessary script tags like script_dependencies(),
        # script_require_udp_ports() or script_mandatory_keys()
        tags_to_remove = list()

        if dependencies := re.search(
            get_special_script_tag_pattern(SpecialScriptTag.DEPENDENCIES),
            file.content,
        ):
            tags_to_remove.append(dependencies.group())

        if udp := re.search(
            get_special_script_tag_pattern(SpecialScriptTag.REQUIRE_UDP_PORTS),
            file.content,
        ):
            tags_to_remove.append(udp.group())

        if man_keys := re.search(
            get_special_script_tag_pattern(SpecialScriptTag.MANDATORY_KEYS),
            file.content,
        ):
            tags_to_remove.append(man_keys.group())

        for tag in tags_to_remove:
            file.content = file.content.replace("  " + tag + "\n", "")

        file.full_path.rename(output_path / file.name)

        with open(output_path / file.name, "w", encoding="latin-1") as f:
            f.write(file.content)
            f.truncate()


def parse_args(args: Iterable[str] = None) -> Namespace:
    parser = ArgumentParser(description="Deprecate VTs")
    parser.add_argument(
        "-o",
        "--output-path",
        metavar="<output_path>",
        type=directory_type,
        required=True,
        help="Path where the deprecated files should be written to.",
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
        "-r",
        "--deprecation-reason",
        metavar="<deprecation_reason>",
        choices=[reason.name for reason in Deprecations],
        type=str,
        help="The reason the VT is being deprecated. Options are 'notus':"
        "The VT has been replaced by a new Notus VT. 'Merged': the VT has"
        "been merged with another still active VT, 'duplicate': The VT has"
        "a still active duplicate, 'defunct': The VT is no longer "
        "functional.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-f",
        "--files",
        metavar="<files>",
        nargs="+",
        default=None,
        type=file_type,
        help="Files to deprecate",
    )
    group.add_argument(
        "-i",
        "--input-path",
        metavar="<input_path>",
        default=None,
        type=directory_type,
        help="Path to the existing nasl script directory",
    )
    return parser.parse_args(args)


def main():
    args = parse_args()
    input_path = args.input_path if args.input_path else None
    filename_prefix = args.filename_prefix

    files = args.files or get_files_from_path(input_path)
    filtered_files = filter_files(files, filename_prefix)

    deprecate(args.output_path, filtered_files, args.deprecation_reason)


if __name__ == "__main__":
    main()

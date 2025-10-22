# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG

import importlib.util
import logging
import re
from argparse import ArgumentParser, Namespace
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable

from pontos.terminal.terminal import ConsoleTerminal

from troubadix.argparser import directory_type, file_type, file_type_existing
from troubadix.helper.patterns import (
    ScriptTag,
    SpecialScriptTag,
    get_script_tag_pattern,
    get_special_script_tag_pattern,
)
from troubadix.troubadix import from_file

logger = logging.getLogger(__name__)


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


def load_transition_oid_mapping(transition_file: Path) -> dict[str, str]:
    spec = importlib.util.spec_from_file_location(
        "transition_layer", transition_file
    )
    transition_layer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transition_layer)

    return transition_layer.mapping


def update_summary(
    file: DeprecatedFile,
    deprecation_reason: str,
    replacement_oid: str | None = None,
) -> str:
    """Update the summary of the nasl script by adding the information
    that the script has been deprecated, and if possible, the oid of
    the new notus script replacing it.

    Args:
        file: DeprecatedFile object containing the content of the VT
        deprecation_reason: The reason this VT is being deprecated,
            from a list of options.
        replacement_oid: The OID of the script that replaces this deprecated one.

    Returns:
        The updated content of the file
    """
    old_summary = _get_summary(file.content)
    if not old_summary:
        logger.warning(f"No summary in: {file.name}")
        return file.content

    deprecate_text = f"Note: This VT has been deprecated {Deprecations[deprecation_reason].value}"

    if replacement_oid:
        deprecate_text += f" The replacement VT has OID {replacement_oid}."

    new_summary = old_summary + "\n\n  " + deprecate_text
    file.content = file.content.replace(old_summary, new_summary)

    return file.content


def _finalize_content(content: str) -> str:
    """Update the content field of the nasl script by adding the
    deprecated tag and removing the extra content."""
    content_to_keep = content.split("exit(0);")[0]
    return content_to_keep + (
        'script_tag(name:"deprecated", value:TRUE);\n\n  exit(0);\n}\n\nexit(66);\n'
    )


def get_files_from_path(dir_path: Path = None) -> list:
    """Get a list of files from the input path provided

    Args:
        dir_path (optional): The path to the directory with the files to
            be deprecated
    """
    return [file for file in dir_path.glob("**/*")]


def parse_files(files: list) -> list[DeprecatedFile]:
    """Convert filepaths into
    DeprecatedFile objects

    Args:
        files: a list of files to deprecate, should be .nasl VTs

    Returns:
        List of DeprecatedFile objects

    """
    to_deprecate = []

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


def _get_summary(content: str) -> str | None:
    """Extract the summary from the nasl script"""
    pattern = get_script_tag_pattern(ScriptTag.SUMMARY)
    if match_summary := re.search(pattern, content):
        value = match_summary.group().split('value:"')[1]
        return value.replace('");', "")
    return None


def find_replacement_oid(
    file: DeprecatedFile,
    oid_mapping: dict[str, str] | None = None,
) -> str | None:
    # Get replacement OID if available
    if not oid_mapping:
        return None

    oid_match = re.search(
        get_special_script_tag_pattern(SpecialScriptTag.OID),
        file.content,
    )
    if not oid_match:
        raise ValueError(
            f"No OID found in {file.name}. Cannot map to replacement OID."
        )
    oid = oid_match.group("value")
    replacement_oid = oid_mapping.get(oid)
    if not replacement_oid:
        raise ValueError(f"No replacement OID found for {oid} in {file.name}.")
    return replacement_oid


def deprecate(
    output_path: Path,
    to_deprecate: list[DeprecatedFile],
    deprecation_reason: str,
    oid_mapping: dict[str, str] | None = None,
) -> None:
    """Deprecate the selected VTs by removing unnecessary keys, updating the
    summary, and adding the deprecated tag.

    Args:
        output_path: the directory where the deprecated VTs should be written
            to, i.e. "attic"
        to_deprecate: the list of files to be deprecated
        deprecation_reason: The reason this VT is being deprecated,
        from a list of options.
        oid_mapping: Optional mapping of file paths to replacement OIDs
    """
    output_path.mkdir(parents=True, exist_ok=True)
    for file in to_deprecate:
        if re.findall(KB_ITEMS_PATTERN, file.content):
            logger.warning(
                f"Unable to deprecate {file.name}. There are still KB keys remaining."
            )
            continue

        replacement_oid = find_replacement_oid(file, oid_mapping)

        file.content = update_summary(file, deprecation_reason, replacement_oid)
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
        required=True,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-f",
        "--file",
        metavar="<file>",
        nargs="+",
        default=None,
        type=file_type,
        help="File to deprecate",
    )
    group.add_argument(
        "-i",
        "--input-path",
        metavar="<input_path>",
        default=None,
        type=directory_type,
        help="Path to a directory where all files should be deprecated.",
    )
    group.add_argument(
        "--from-file",
        metavar="<from_file>",
        default=None,
        type=file_type_existing,
        help=(
            "Path to a single file that contains a list of files "
            "to be deprecated, separated by new lines."
        ),
    )

    parser.add_argument(
        "--transition-file",
        metavar="<transition_file>",
        default=None,
        type=file_type_existing,
        help=(
            "Path to a file containing a list of oid mappings."
            "Found in notus/generator/nasl/transition_layer."
        ),
    )
    return parser.parse_args(args)


def main():
    args = parse_args()
    terminal = ConsoleTerminal()
    input_path = args.input_path if args.input_path else None
    files = []

    if input_path:
        files = get_files_from_path(input_path)
    elif args.from_file:
        files = from_file(include_file=args.from_file, term=terminal)
    elif args.file:
        files = args.file

    # Load OID mapping if provided
    oid_mapping = None
    if args.transition_file:
        oid_mapping = load_transition_oid_mapping(args.transition_file)

    deprecate(
        args.output_path,
        parse_files(files),
        args.deprecation_reason,
        oid_mapping,
    )


if __name__ == "__main__":
    main()

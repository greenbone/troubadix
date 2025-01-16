# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG
import logging
import os
import re
import sys
from argparse import ArgumentParser, Namespace
from dataclasses import dataclass
from pathlib import Path

import networkx as nx

from troubadix.helper import CURRENT_ENCODING
from troubadix.helper.helper import is_enterprise_folder
from troubadix.helper.patterns import (
    ScriptTag,
    SpecialScriptTag,
    _get_special_script_tag_pattern,
    get_script_tag_pattern,
    get_special_script_tag_pattern,
)
from troubadix.plugins.dependency_category_order import (
    VTCategory,
)

EXTENSIONS = (".nasl",)  # not sure if inc files can also have dependencies
DEPENDENCY_PATTERN = _get_special_script_tag_pattern(
    "dependencies", flags=re.DOTALL | re.MULTILINE
)
CATEGORY_PATTERN = get_special_script_tag_pattern(SpecialScriptTag.CATEGORY)
DEPRECATED_PATTERN = get_script_tag_pattern(ScriptTag.DEPRECATED)
IF_BLOCK_PATTERN = re.compile(
    r'if\s*\(FEED_NAME\s*==\s*"GSF"\s*\|\|\s*FEED_NAME\s*==\s*"GEF"\s*\|\|\s*FEED_NAME\s*==\s*"SCM"\)\s*'
    r"(?:\{[^}]*\}\s*|[^\{;]*;)"
)  # Matches specific if blocks used to gate code to run only for enterprise feeds


@dataclass
class Script:
    name: str
    feed: str
    dependencies: list[tuple[str, bool]]  # (dependency_name, is_gated)
    category: int
    deprecated: bool


def directory_type(string: str) -> Path:
    directory_path = Path(string)
    if not directory_path.is_dir():
        raise ValueError(f"{string} is not a directory.")
    return directory_path


def parse_args() -> Namespace:
    parser = ArgumentParser(
        description="Tool for analysing the dependencies in the NASL repository.",
    )
    parser.add_argument(
        "root",
        type=directory_type,
        help="directory that should be linted",
    )
    parser.add_argument(
        "--feed",
        choices=["21.04", "22.04", "common", "full"],
        default="full",
        help="feed",
    )
    parser.add_argument(
        "--log",
        default="WARNING",
        help="Set the logging level (INFO, WARNING, ERROR)",
    )
    return parser.parse_args()


# Usefull? Or is full only ever used and can therfore be removed?
def get_feed(root, feed) -> list[Script]:
    match feed:
        case "21.04":
            return get_scripts(root / "common") + get_scripts(root / "21.04")
        case "22.04":
            return get_scripts(root / "common") + get_scripts(root / "22.04")
        case "common":
            return get_scripts(root / "common")
        case "full":
            return (
                get_scripts(root / "common")
                + get_scripts(root / "21.04")
                + get_scripts(root / "22.04")
            )
        case _:
            return []


def get_scripts(directory) -> list[Script]:
    scripts = []
    # use path glob?
    file_generator = (
        (Path(root) / file_str)
        for root, _, files in os.walk(directory)
        for file_str in files
        if file_str.endswith(EXTENSIONS)
    )

    for path in file_generator:
        try:
            content = path.read_text(encoding=CURRENT_ENCODING)
        except Exception as e:
            logging.error(f"Error reading file {path}: {e}")
            continue

        try:
            relative_path = path.relative_to(directory)  # used as identifier
            name = str(relative_path)
            feed = determine_feed(relative_path)
            dependencies = extract_dependencies(content)
            category = extract_category(content)
            deprecated = extract_deprecated_status(content)
            scripts.append(
                Script(name, feed, dependencies, category, deprecated)
            )
        except Exception as e:
            logging.error(f"Error processing {path}: {e}")

    return scripts


def determine_feed(script_relative_path: Path) -> str:
    parts = script_relative_path.parts
    if is_enterprise_folder(parts[0]):
        return "enterprise"
    else:
        return "community"


def extract_deprecated_status(content) -> bool:
    return bool(DEPRECATED_PATTERN.search(content))


def split_dependencies(value: str) -> list[str]:
    """
    removes blank lines, strips comments, cleans dependencies,
    splits them by commas, and excludes empty strings.
    """
    return [
        dep
        for line in value.splitlines()
        if line.strip()  # Ignore blank or whitespace-only lines
        # ignore comment, clean line of unwanted chars, split by ','
        for dep in re.sub(r'[\'"\s]', "", line.split("#", 1)[0]).split(",")
        if dep  # Include only non-empty
    ]


def extract_dependencies(content: str) -> list[tuple[str, bool]]:
    dependencies = []

    if_blocks = [
        (match.start(), match.end())
        for match in IF_BLOCK_PATTERN.finditer(content)
    ]

    for match in DEPENDENCY_PATTERN.finditer(content):
        start, end = match.span()
        is_gated = any(
            start >= block_start and end <= block_end
            for block_start, block_end in if_blocks
        )
        dep_list = split_dependencies(match.group("value"))
        dependencies.extend((dep, is_gated) for dep in dep_list)

    return dependencies


def extract_category(content) -> int:
    match = CATEGORY_PATTERN.search(content)
    category_value = match.group("value")
    return VTCategory[category_value]


def create_graph(scripts: list[Script]):
    graph = nx.DiGraph()

    # Add nodes and edges based on dependencies
    for script in scripts:
        # explicit add incase the script has no dependencies
        graph.add_node(
            script.name,
            feed=script.feed,
            category=script.category,
            deprecated=script.deprecated,
        )
        for dep, is_gated in script.dependencies:
            graph.add_edge(script.name, dep, is_gated=is_gated)
    return graph


def check_duplicates(scripts: list[Script]):
    """
    checks for a script depending on a script multiple times
    """
    for script in scripts:
        dependencies = [dep for dep, _ in script.dependencies]
        duplicates = {
            dep for dep in dependencies if dependencies.count(dep) > 1
        }
        if duplicates:
            logging.warning(
                f"Duplicate dependencies in {script.name}: {', '.join(duplicates)}"
            )


def check_missing_dependencies(scripts: list[Script], graph: nx.DiGraph) -> int:
    """
    Checks if any scripts that are depended on are missing from
    the list of scripts created from the local file system,
    logs the scripts dependending on the missing script
    """
    dependencies = {dep for script in scripts for dep, _ in script.dependencies}
    script_names = {script.name for script in scripts}
    missing_dependencies = dependencies - script_names
    if not missing_dependencies:
        return 0

    for missing in missing_dependencies:
        depending_scripts = graph.predecessors(missing)
        logging.error(f"missing dependency file: {missing}:")
        for script in depending_scripts:
            logging.info(f"  - used by: {script}")

    return 1


def check_cycles(graph) -> int:
    """
    checks for cyclic dependencies
    """
    if nx.is_directed_acyclic_graph(graph):
        return 0

    cyles = nx.simple_cycles(graph)
    for cycle in cyles:
        logging.error(f"cyclic dependency: {cycle}")

    return 1


def cross_feed_dependencies(graph, gated_status: bool):
    """
    creates a list of script and dependency for scripts
    in community feed that depend on scripts in enterprise folders
    """
    cross_feed_dependencies = [
        (u, v)
        for u, v, is_gated in graph.edges.data("is_gated")
        if graph.nodes[u]["feed"] == "community"
        and graph.nodes[v].get("feed", "unknown") == "enterprise"
        and is_gated == gated_status
    ]  # unknown as standard value due to non existend nodes not having a feed value
    return cross_feed_dependencies


def check_cross_feed_dependecies(graph):
    """
    Checks if scripts in the community feed have dependencies to enterprise scripts,
    and if they are contained within a gate.
    """
    gated_cfd = cross_feed_dependencies(graph, gated_status=True)
    for dependent, dependency in gated_cfd:
        logging.info(
            f"gated cross-feed-dependency: {dependent} depends on {dependency}"
        )

    ungated_cfd = cross_feed_dependencies(graph, gated_status=False)
    if not ungated_cfd:
        return 0
    for dependent, dependency in ungated_cfd:
        logging.error(
            f"ungated cross-feed-dependency: {dependent} depends on {dependency}"
        )

    return 1


def check_category_order(graph):
    problematic_edges = [
        (dependent, dependency)
        for dependent, dependency in graph.edges()
        if graph.nodes[dependent]["category"]
        < graph.nodes[dependency].get("category", -1)
    ]

    if not problematic_edges:
        return 0
    for dependent, dependency in problematic_edges:
        logging.error(
            "Not allowed category order."
            f" {dependent} is higher in the execution order than {dependency}"
        )
    return 1


def check_deprecated_dependencies(graph) -> int:
    deprecated_edges = [
        (dependent, dependency)
        for dependent, dependency in graph.edges()
        if graph.nodes[dependency].get("deprecated", False)
    ]
    if not deprecated_edges:
        return 0
    for dependent, dependency in deprecated_edges:
        logging.error(
            f"Deprecated dependency: {dependent} depends on {dependency}"
        )
    return 1


def main():
    args = parse_args()
    logging.basicConfig(
        level=args.log.upper(), format="%(levelname)s: %(message)s"
    )
    logging.info("starting troubadix dependency analysis")

    scripts = get_feed(args.root, args.feed)
    graph = create_graph(scripts)

    logging.info(f"nodes (scripts) in graph: {graph.number_of_nodes()}")
    logging.info(f"edges (dependencies) in graph: {graph.number_of_edges()}")

    failed = 0

    check_duplicates(scripts)
    failed += check_missing_dependencies(scripts, graph)
    failed += check_cycles(graph)
    failed += check_cross_feed_dependecies(graph)
    failed += check_category_order(graph)
    failed += check_deprecated_dependencies(graph)

    return failed


if __name__ == "__main__":
    sys.exit(main())

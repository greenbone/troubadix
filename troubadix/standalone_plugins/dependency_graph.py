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
from troubadix.helper.patterns import _get_special_script_tag_pattern

EXTENSIONS = (".nasl",)  # not sure if inc files can also have dependencies
DEPENDENCY_PATTERN = _get_special_script_tag_pattern(
    "dependencies", flags=re.DOTALL | re.MULTILINE
)
IF_BLOCK_PATTERN = re.compile(
    r'if\s*\(FEED_NAME\s*==\s*"GSF"\s*\|\|\s*FEED_NAME\s*==\s*"GEF"\s*\|\|\s*FEED_NAME\s*==\s*"SCM"\)\s*'
    r"(?:\{[^}]*\}\s*|[^\{;]*;)"
)  # Matches specific if blocks used to gate code to run only for enterprise feeds


@dataclass
class Script:
    name: str
    path: Path
    feed: str
    ungated_dependencies: list[str]  # not in a enterprise gate
    gated_dependencies: list[str]  # inside a enterprise gate

    @property
    def dependencies(self) -> list[str]:
        return self.ungated_dependencies + self.gated_dependencies


def directory_type(string: str) -> Path:
    directory_path = Path(string)
    if not directory_path.is_dir():
        raise ValueError(f"{string} is not a directory.")
    return directory_path


def parse_args() -> Namespace:
    parser = ArgumentParser(
        description="Check for files with unwanted file extensions",
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
    for root, _, files in os.walk(directory):
        root_path = Path(root)
        for file in files:
            if file.endswith(EXTENSIONS):
                path = root_path / file  # absolute path for file access
                relative_path = path.relative_to(
                    directory
                )  # relative path to \nasl will be used as identifier
                name = str(relative_path)
                feed = determine_feed(relative_path)
                ungated_dependencies, gated_dependencies = extract_dependencies(
                    path
                )
                scripts.append(
                    Script(
                        name,
                        path,
                        feed,
                        ungated_dependencies,
                        gated_dependencies,
                    )
                )
    return scripts


def determine_feed(script_relative_path: Path) -> str:
    parts = script_relative_path.parts
    if is_enterprise_folder(parts[0]):
        return "enterprise"
    else:
        return "community"


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


def extract_dependencies(file_path: Path) -> tuple[list[str], list[str]]:
    ungated_deps = []
    gated_deps = []

    try:
        with file_path.open("r", encoding=CURRENT_ENCODING) as file:
            content = file.read()

        if_blocks = [
            (m.start(), m.end()) for m in IF_BLOCK_PATTERN.finditer(content)
        ]

        for match in DEPENDENCY_PATTERN.finditer(content):
            start, end = match.span()
            is_gated = any(
                start >= block_start and end <= block_end
                for block_start, block_end in if_blocks
            )
            dependencies = split_dependencies(match.group("value"))
            (gated_deps if is_gated else ungated_deps).extend(dependencies)

    except Exception as e:
        logging.error(f"Error processing {file_path}: {e}")

    return (ungated_deps, gated_deps)


def create_graph(scripts: list[Script]):
    graph = nx.DiGraph()

    # Add nodes and edges based on dependencies
    for script in scripts:
        # explicit add incase the script has no dependencies
        graph.add_node(script.name, feed=script.feed)
        for dep in script.ungated_dependencies:
            graph.add_edge(script.name, dep, is_gated=False)
        for dep in script.gated_dependencies:
            graph.add_edge(script.name, dep, is_gated=True)
    return graph


def check_duplicates(scripts: list[Script]):
    """
    checks for a script depending on a script multiple times
    """
    for script in scripts:
        duplicates = {
            dep
            for dep in script.dependencies
            if script.dependencies.count(dep) > 1
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
    dependencies = {dep for script in scripts for dep in script.dependencies}
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
    logging.info(f" {len(gated_cfd)} gated cross-feed-dependencies were found:")
    for u, v in gated_cfd:
        logging.info(f"gated cross-feed-dependency: {u} depends on {v}")

    ungated_cfd = cross_feed_dependencies(graph, gated_status=False)
    logging.info(
        f" {len(ungated_cfd)} ungated cross-feed-dependencies were found:"
    )
    for u, v in ungated_cfd:
        logging.error(f"ungated cross-feed-dependency: {u} depends on {v}")

    if ungated_cfd:
        return 1
    else:
        return 0


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

    return failed


if __name__ == "__main__":
    sys.exit(main())

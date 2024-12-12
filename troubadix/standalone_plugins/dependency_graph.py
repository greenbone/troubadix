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

EXTENSIONS = (".nasl",)
DEPENDENCY_REGEX = r"script_dependencies\((.*?)\);"
DEPENDENCY_PATTERN = _get_special_script_tag_pattern(
    "dependencies", flags=re.DOTALL | re.MULTILINE
)


@dataclass
class Script:
    name: str
    path: Path
    feed: str
    dependencies: list[str]


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
                path = root_path / file
                relative_path = path.relative_to(directory)
                name = str(relative_path)
                feed = determine_feed(relative_path)
                dependencies = extract_dependencies(path)
                scripts.append(Script(name, path, feed, dependencies))
    return scripts


def determine_feed(script_relative_path: Path) -> str:
    parts = script_relative_path.parts
    if is_enterprise_folder(parts[0]):
        return "enterprise"
    else:
        return "community"


# works but not used, skips gsf folder
# could be used to only determine a scripts feed
# by only fetching from enterprise folder in a seperate call
def community_files(directory):
    enterprise_dir = directory / "gsf"
    for root, dirs, files in os.walk(directory):
        root_path = Path(root)
        # durch edit in place wird gsf folder ausgelassen
        dirs[:] = [d for d in dirs if root_path / d != enterprise_dir]
        for file in files:
            if file.endswith(EXTENSIONS):
                yield root_path / file


def extract_dependencies(file_path: Path) -> list[str]:
    deps = []

    try:
        with file_path.open("r", encoding=CURRENT_ENCODING) as file:
            content = file.read()

        matches = DEPENDENCY_PATTERN.finditer(content)
        for match in matches:
            for line in match.group("value").splitlines():
                subject = line[: line.index("#")] if "#" in line else line
                _dependencies = re.sub(r'[\'"\s]', "", subject).split(",")
                deps.extend([dep for dep in _dependencies if dep != ""])

    except Exception as e:
        logging.error(f"Error processing {file_path}: {e}")

    return deps


def create_graph(scripts: list[Script]):
    graph = nx.DiGraph()

    # Add nodes and edges based on dependencies
    for script in scripts:
        # explicit add incase the script has no dependencies
        graph.add_node(script.name, feed=script.feed)
        for dep in script.dependencies:
            graph.add_edge(script.name, dep)
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
    checks if any scripts that are depended on are missing from the list of scripts

    also logs the scripts dependending on the missing script
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


def cross_feed_dependencies(graph):
    """
    checks if scripts in community depend on scripts in enterprise folders
    """
    cross_feed_dependencies = [
        (u, v)
        for u, v in graph.edges
        if graph.nodes[u]["feed"] == "community"
        and graph.nodes[v].get("feed", "unknown") == "enterprise"
    ]
    for u, v in cross_feed_dependencies:
        logging.info(f"cross-feed-dependency: {u} depends on {v}")


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
    cross_feed_dependencies(graph)

    return failed


if __name__ == "__main__":
    sys.exit(main())

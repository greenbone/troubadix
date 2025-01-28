# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG
import logging
import os
import re
import sys
from argparse import ArgumentParser, ArgumentTypeError, Namespace
from dataclasses import dataclass, field
from enum import Flag, auto
from functools import reduce
from pathlib import Path
from typing import NamedTuple

import networkx as nx

from troubadix.argparser import directory_type_existing
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

DEPENDENCY_PATTERN = _get_special_script_tag_pattern(
    "dependencies", flags=re.DOTALL | re.MULTILINE
)
CATEGORY_PATTERN = get_special_script_tag_pattern(SpecialScriptTag.CATEGORY)
DEPRECATED_PATTERN = get_script_tag_pattern(ScriptTag.DEPRECATED)
ENTERPRISE_FEED_CHECK_PATTERN = re.compile(
    r'if\s*\(FEED_NAME\s*==\s*"GSF"\s*\|\|\s*FEED_NAME\s*==\s*"GEF"\s*\|\|\s*FEED_NAME\s*==\s*"SCM"\)\s*'
    r"(?:\{[^}]*\}\s*|[^\{;]*;)"
)  # Matches specific if blocks used to gate code to run only for enterprise feeds


class Feed(Flag):
    COMMON = auto()
    FEED_21_04 = auto()
    FEED_22_04 = auto()
    FULL = COMMON | FEED_21_04 | FEED_22_04

    def __str__(self):
        # Make enum values user-friendly for argparse help
        return self.name.lower()


def feed_type(value: str) -> Feed:
    try:
        return Feed[value.upper()]
    except KeyError:
        raise ArgumentTypeError(f"Invalid Feed value: '{value}'")


class Dependency(NamedTuple):
    name: str
    # Indicates whether the dependency will only run if an enterprise feed is used.
    # Controlled by a specific if check. Does not indicate the script's feed.
    is_enterprise_feed: bool


@dataclass
class Script:
    name: str
    feed: str
    dependencies: list[Dependency]
    category: int
    deprecated: bool


@dataclass
class Result:
    name: str
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def has_errors(self) -> bool:
        return bool(self.errors)

    def has_warnings(self) -> bool:
        return bool(self.warnings)


class Reporter:
    def __init__(self, verbosity) -> None:
        self.verbosity = verbosity

    def report(self, results: list[Result]):
        for result in results:
            if self.verbosity >= 2:
                self.print_statistic(result)
                self.print_divider()
            if self.verbosity >= 1:
                self.print_warnings(result)
            self.print_errors(result)
            if self.verbosity >= 2:
                self.print_divider("=")

    def print_divider(self, char="-", length=40):
        print(char * length)

    def print_statistic(self, result: Result):
        print(
            f"{result.name} - warnings: {len(result.warnings)}, errors: {len(result.errors)}"
        )

    def print_warnings(self, result: Result):
        for warning in result.warnings:
            print(f"warning: {warning}")

    def print_errors(self, result: Result):
        for error in result.errors:
            print(f"error: {error}")


def parse_args() -> Namespace:
    parser = ArgumentParser(
        description="Tool for analysing the dependencies in the NASL repository.",
    )
    parser.add_argument(
        "root",
        type=directory_type_existing,
        nargs="?",
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

    return parser.parse_args()


def get_feed(root, feeds: list[Feed]) -> list[Script]:
    feed = reduce((lambda x, y: x | y), feeds)
    scripts = []
    if feed & Feed.COMMON:
        scripts.extend(get_scripts(root / "common"))
    if feed & Feed.FEED_21_04:
        scripts.extend(get_scripts(root / "21.04"))
    if feed & Feed.FEED_22_04:
        scripts.extend(get_scripts(root / "22.04"))

    return scripts


def get_scripts(directory: Path) -> list[Script]:
    scripts = []

    for path in directory.rglob("*.nasl"):
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
            deprecated = bool(DEPRECATED_PATTERN.search(content))
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


def extract_dependencies(content: str) -> list[Dependency]:
    dependencies = []

    if_blocks = [
        (match.start(), match.end())
        for match in ENTERPRISE_FEED_CHECK_PATTERN.finditer(content)
    ]

    for match in DEPENDENCY_PATTERN.finditer(content):
        start, end = match.span()
        is_enterprise_feed = any(
            start >= block_start and end <= block_end
            for block_start, block_end in if_blocks
        )
        dep_list = split_dependencies(match.group("value"))
        dependencies.extend(
            Dependency(dep, is_enterprise_feed) for dep in dep_list
        )

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
        for dependency in script.dependencies:
            graph.add_edge(
                script.name,
                dependency.name,
                is_enterprise_feed=dependency.is_enterprise_feed,
            )
    return graph


def check_duplicates(scripts: list[Script]) -> Result:
    """
    checks for a script depending on a script multiple times
    """
    warnings = []
    for script in scripts:
        dependencies = [dep for dep, _ in script.dependencies]
        duplicates = {
            dep for dep in dependencies if dependencies.count(dep) > 1
        }
        if duplicates:
            msg = f"Duplicate dependencies in {script.name}: {', '.join(duplicates)}"
            warnings.append(msg)

    return Result(name="check_duplicates", warnings=warnings)


def check_missing_dependencies(
    scripts: list[Script], graph: nx.DiGraph
) -> Result:
    """
    Checks if any scripts that are depended on are missing from
    the list of scripts created from the local file system,
    logs the scripts dependending on the missing script
    """
    errors = []
    dependencies = {
        dep.name for script in scripts for dep in script.dependencies
    }
    script_names = {script.name for script in scripts}
    missing_dependencies = dependencies - script_names

    for missing in missing_dependencies:
        depending_scripts = graph.predecessors(missing)
        msg = f"missing dependency file: {missing}:"
        for script in depending_scripts:
            msg += f"\n  - used by: {script}"
        errors.append(msg)

    return Result(name="missing_dependencies", errors=errors)


def check_cycles(graph) -> Result:
    """
    checks for cyclic dependencies
    """
    if nx.is_directed_acyclic_graph(graph):
        return Result(name="check_cycles")

    cycles = nx.simple_cycles(graph)

    errors = [f"cyclic dependency: {cycle}" for cycle in cycles]
    return Result(name="check_cycles", errors=errors)


def cross_feed_dependencies(
    graph, is_enterprise_checked: bool
) -> list[tuple[str, str]]:
    """
    creates a list of script and dependency for scripts
    in community feed that depend on scripts in enterprise folders
    """
    cross_feed_dependencies = [
        (u, v)
        for u, v, is_enterprise_feed in graph.edges.data("is_enterprise_feed")
        if graph.nodes[u]["feed"] == "community"
        and graph.nodes[v].get("feed", "unknown") == "enterprise"
        and is_enterprise_feed == is_enterprise_checked
    ]  # unknown as standard value due to non existend nodes not having a feed value
    return cross_feed_dependencies


def check_cross_feed_dependecies(graph) -> Result:
    """
    Checks if scripts in the community feed have dependencies to enterprise scripts,
    and if they are correctly contained within a is_enterprise_feed check.
    """
    gated_cfd = cross_feed_dependencies(graph, is_enterprise_checked=True)
    warnings = [
        f"cross-feed-dependency: {dependent}(community feed) "
        f"depends on {dependency}(enterprise feed)"
        for dependent, dependency in gated_cfd
    ]

    ungated_cfd = cross_feed_dependencies(graph, is_enterprise_checked=False)
    errors = [
        f"unchecked cross-feed-dependency: {dependent}(community feed) "
        f"depends on {dependency}(enterprise feed), but the current feed is not properly checked"
        for dependent, dependency in ungated_cfd
    ]

    return Result(
        name="check_cross_feed_dependencies", warnings=warnings, errors=errors
    )


def check_category_order(graph) -> Result:
    problematic_edges = [
        (dependent, dependency)
        for dependent, dependency in graph.edges()
        if graph.nodes[dependent]["category"]
        < graph.nodes[dependency].get("category", -1)
    ]

    errors = [
        f"{dependent} depends on {dependency} which has a lower category order"
        for dependent, dependency in problematic_edges
    ]
    return Result(name="check_category_order", errors=errors)


def check_deprecated_dependencies(graph) -> Result:
    errors = [
        f"{dependent} depends on deprectated script {dependency}"
        for dependent, dependency in graph.edges()
        if graph.nodes[dependency].get("deprecated", False)
    ]
    return Result(name="check_deprecated_dependencies", errors=errors)


def main():
    args = parse_args()

    logging.basicConfig(
        level=args.log.upper(), format="%(levelname)s: %(message)s"
    )
    if args.root is None:
        vtdir = os.environ.get("VTDIR")
        if not vtdir:
            raise RuntimeError(
                "The environment variable 'VTDIR' is not set, and no path was provided."
            )
        args.root = Path(vtdir)
        logging.info(f"using root {vtdir} from 'VTDIR'")

    logging.info("starting troubadix dependency analysis")

    scripts = get_feed(args.root, args.feed)
    graph = create_graph(scripts)

    logging.info(f"nodes (scripts) in graph: {graph.number_of_nodes()}")
    logging.info(f"edges (dependencies) in graph: {graph.number_of_edges()}")

    results = [
        check_duplicates(scripts),
        check_missing_dependencies(scripts, graph),
        check_cycles(graph),
        check_cross_feed_dependecies(graph),
        check_category_order(graph),
        check_deprecated_dependencies(graph),
    ]
    reporter = Reporter(args.verbose)
    reporter.report(results)

    if any(result.has_errors() for result in results):
        return 1
    elif any(result.has_warnings() for result in results):
        return 2
    else:
        return 0


if __name__ == "__main__":
    sys.exit(main())

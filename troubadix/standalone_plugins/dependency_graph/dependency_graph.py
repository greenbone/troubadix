# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG


import logging
import re
import sys
from functools import reduce
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
from troubadix.plugins.dependencies import split_dependencies
from troubadix.plugins.dependency_category_order import (
    VTCategory,
)

from .checks import (
    check_category_order,
    check_cross_feed_dependencies,
    check_cycles,
    check_deprecated_dependencies,
    check_duplicates,
    check_missing_dependencies,
)
from .cli import Feed, parse_args
from .models import Dependency, Result, Script

DEPENDENCY_PATTERN = _get_special_script_tag_pattern(
    "dependencies", flags=re.DOTALL | re.MULTILINE
)
CATEGORY_PATTERN = get_special_script_tag_pattern(SpecialScriptTag.CATEGORY)
DEPRECATED_PATTERN = get_script_tag_pattern(ScriptTag.DEPRECATED)
ENTERPRISE_FEED_CHECK_PATTERN = re.compile(
    r'if\s*\(FEED_NAME\s*==\s*"GSF"\s*\|\|\s*FEED_NAME\s*==\s*"GEF"\s*\|\|\s*FEED_NAME\s*==\s*"SCM"\)\s*'
    r"(?:\{[^}]*\}\s*|[^\{;]*;)"
)  # Matches specific if blocks used to gate code to run only for enterprise feeds


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

    results = [
        check_duplicates(scripts),
        check_missing_dependencies(scripts, graph),
        check_cycles(graph),
        check_cross_feed_dependencies(graph),
        check_category_order(graph),
        check_deprecated_dependencies(graph),
    ]
    reporter = Reporter(args.verbose)
    reporter.report(results)

    if any(result.errors for result in results):
        return 1
    elif any(result.warnings for result in results):
        return 2
    else:
        return 0


if __name__ == "__main__":
    sys.exit(main())

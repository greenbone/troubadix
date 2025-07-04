# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG


import logging
import re
import sys
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

logging.basicConfig(format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


class Reporter:
    def report(self, results: list[Result]):
        for result in results:
            for error in result.errors:
                logger.error(f"{result.name}: {error}")
            for warning in result.warnings:
                logger.warning(f"{result.name}: {warning}")
            for info in result.infos:
                logger.info(f"{result.name}: {info}")


def get_feed(root: Path, feed: Feed) -> list[Script]:
    scripts = get_scripts(root / "common")  # Always include common
    if feed != Feed.COMMON:  # Add version-specific scripts if not just common
        scripts.extend(get_scripts(root / feed.value))

    return scripts


def get_scripts(directory: Path) -> list[Script]:
    scripts = []

    for path in directory.rglob("*.nasl"):
        try:
            content = path.read_text(encoding=CURRENT_ENCODING)
        except Exception as e:
            logger.error(f"Error reading file {path}: {e}")
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
            logger.error(f"Error processing {path}: {e}")

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

    logger.setLevel(args.log)

    logger.info("starting troubadix dependency analysis")

    scripts = get_feed(args.root, args.feed)
    graph = create_graph(scripts)

    logger.info(f"nodes (scripts) in graph: {graph.number_of_nodes()}")
    logger.info(f"edges (dependencies) in graph: {graph.number_of_edges()}")

    results = [
        check_duplicates(scripts),
        check_missing_dependencies(scripts, graph),
        check_cycles(graph),
        check_cross_feed_dependencies(graph),
        check_category_order(graph),
        check_deprecated_dependencies(graph),
    ]
    reporter = Reporter()
    reporter.report(results)

    if any(result.errors for result in results):
        return 1
    elif any(result.warnings for result in results):
        return 2
    else:
        return 0


if __name__ == "__main__":
    sys.exit(main())

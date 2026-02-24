# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG


import logging
import re
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
from troubadix.helper.remove_comments import remove_comments
from troubadix.plugins.dependencies import split_dependencies
from troubadix.plugins.dependency_category_order import VTCategory

from .models import Dependency, Feed, Script

DEPENDENCY_PATTERN = _get_special_script_tag_pattern("dependencies", flags=re.DOTALL | re.MULTILINE)
INCLUDE_PATTERN = re.compile(r'include\s*\(\s*(?P<quote>[\'"])(?P<value>.*?)(?P=quote)\s*\)\s*;')
CATEGORY_PATTERN = get_special_script_tag_pattern(SpecialScriptTag.CATEGORY)
DEPRECATED_PATTERN = get_script_tag_pattern(ScriptTag.DEPRECATED)

ENTERPRISE_FEED_CHECK_PATTERN = re.compile(
    r'if\s*\(FEED_NAME\s*==\s*"GSF"\s*\|\|\s*FEED_NAME\s*==\s*"GEF"\s*\|\|\s*FEED_NAME\s*==\s*"SCM"\)\s*'
    r"(?:\{[^}]*\}\s*|[^\{;]*;)"
)  # Matches specific if blocks used to gate code to run only for enterprise feeds

NASL_EXTENSIONS = (".nasl", ".inc")

logger = logging.getLogger(__name__)


def get_feed(root: Path, feed: Feed) -> list[Script]:
    scripts = get_scripts(root / "common")  # Always include common
    if feed != Feed.COMMON:  # Add version-specific scripts if not just common
        scripts.extend(get_scripts(root / feed.value))

    return scripts


def get_scripts(directory: Path) -> list[Script]:
    scripts = []

    for path in directory.rglob("*"):
        if path.suffix not in NASL_EXTENSIONS or not path.is_file():
            continue

        try:
            content = path.read_text(encoding=CURRENT_ENCODING)
            content = remove_comments(content)

            relative_path = path.relative_to(directory)  # used as identifier
            name = str(relative_path)
            feed = determine_feed(relative_path)
            dependencies = extract_dependencies(content)
            category = extract_category(content)
            deprecated = bool(DEPRECATED_PATTERN.search(content))
            scripts.append(Script(name, feed, dependencies, category, deprecated))
        except Exception as e:
            logger.error(f"Error processing {path}: {e}")
            raise

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
        (match.start(), match.end()) for match in ENTERPRISE_FEED_CHECK_PATTERN.finditer(content)
    ]

    for match in DEPENDENCY_PATTERN.finditer(content):
        start, end = match.span()
        is_enterprise_feed = any(
            start >= block_start and end <= block_end for block_start, block_end in if_blocks
        )
        dep_list = split_dependencies(match.group("value"))
        dependencies.extend(Dependency(dep, is_enterprise_feed) for dep in dep_list)

    for match in INCLUDE_PATTERN.finditer(content):
        start, end = match.span()
        is_enterprise_feed = any(
            start >= block_start and end <= block_end for block_start, block_end in if_blocks
        )
        dependencies.append(Dependency(match.group("value"), is_enterprise_feed))

    return dependencies


def extract_category(content) -> int:
    match = CATEGORY_PATTERN.search(content)
    if not match:
        return -1
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


def create_barebones_dependency_graph(root: Path, feed: Feed) -> nx.DiGraph:
    """
    Build a dependency graph with only script names and dependency edges.
    Skips category, deprecated, and enterprise feed checks for speed.
    """
    graph = nx.DiGraph()

    script_dirs = [root / "common"]
    if feed != Feed.COMMON:
        script_dirs.append(root / feed.value)

    for directory in script_dirs:
        for path in directory.rglob("*"):
            if path.suffix not in NASL_EXTENSIONS or not path.is_file():
                continue
            try:
                content = path.read_text(encoding=CURRENT_ENCODING)
                relative_path = path.relative_to(directory)
                name = str(relative_path)

                for match in INCLUDE_PATTERN.finditer(content):
                    dep_name = match.group("value")
                    graph.add_edge(name, dep_name)
                for match in DEPENDENCY_PATTERN.finditer(content):
                    dep_list = split_dependencies(match.group("value"))
                    for dep in dep_list:
                        graph.add_edge(name, dep)
            except Exception as e:
                logger.error(f"Error processing {path}: {e}")
                raise
    return graph


def create_barebones_dependency_graph_from_root(root: Path) -> nx.DiGraph:
    """
    Build a dependency graph scanning a single root directory where all
    NASL files already live (e.g. generated feed layout under vt-data/nasl).
    This is a slimmed-down scanner that only extracts dependency and include
    relationships and does not perform any feed-specific logic.
    """
    graph = nx.DiGraph()

    for path in Path(root).rglob("*"):
        if path.suffix not in NASL_EXTENSIONS or not path.is_file():
            continue
        try:
            content = path.read_text(encoding=CURRENT_ENCODING)
            relative_path = path.relative_to(root)
            name = str(relative_path)

            for match in INCLUDE_PATTERN.finditer(content):
                dep_name = match.group("value")
                graph.add_edge(name, dep_name)
            for match in DEPENDENCY_PATTERN.finditer(content):
                dep_list = split_dependencies(match.group("value"))
                for dep in dep_list:
                    graph.add_edge(name, dep)
        except Exception as e:
            logger.error(f"Error processing {path}: {e}")
            raise

    return graph

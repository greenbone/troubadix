# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG


import logging
import sys

from .checks import (
    check_category_order,
    check_cross_feed_dependencies,
    check_cycles,
    check_deprecated_dependencies,
    check_duplicates,
    check_missing_dependencies,
)
from .cli import parse_args
from .graph_builder import create_graph, get_feed
from .models import Result

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

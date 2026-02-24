# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG


import argparse
import re
from pathlib import Path

import networkx as nx

from troubadix.argparser import directory_type_existing, file_type, file_type_existing

from .graph_builder import create_barebones_dependency_graph_from_root


def run(
    feed_root: Path,
    input_file: Path,
    output_file: Path,
    max_distance: int = None,
):
    # feed_root is expected to point to the generated feed NASL directory
    graph = create_barebones_dependency_graph_from_root(feed_root)
    changed_files = input_file.read_text().splitlines()

    affected = set()

    # Reversing the graph allows us to find dependents (ancestors) by
    # traversing "downstream" in the reversed version. This is more
    # efficient for distance-limited searches using standard algorithms.
    rev_graph = graph.reverse() if max_distance is not None else None

    for line in changed_files:
        line = line.strip()
        if not line:
            continue

        # Examples of changed lines: nasl/common/foo.nasl or nasl/21.04/foo.nasl
        # Replaces ^nasl/(common|21\.04|22\.04)/ with an empty string,
        # leaving the relative feed path.
        name = re.sub(r"^nasl/(common|21\.04|22\.04)/", "", line)

        if name in graph:
            affected.add(name)
            if max_distance is None:
                # Find all scripts that depend on the changed script (ancestors)
                affected.update(nx.ancestors(graph, name))
            else:
                # Find dependents up to a specific distance.
                # We traverse the reversed graph starting from 'name'; nodes
                # reachable within 'max_distance' steps are its dependents.
                lengths = nx.single_source_shortest_path_length(
                    rev_graph, name, cutoff=max_distance
                )
                affected.update(lengths.keys())

    # output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text("\n".join(sorted(affected)) + "\n")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Purpose-built tool for the PR QA checks workflow. Finds scripts affected by "
            "changes based on dependency graph (generated-feed layout)."
        )
    )
    parser.add_argument(
        "feed_root",
        type=directory_type_existing,
        help="Root directory of the generated feed NASL tree (e.g., vt-data/nasl)",
    )
    parser.add_argument(
        "input_file",
        type=file_type_existing,
        help=(
            "Path to the file containing the list of changed scripts in repository "
            "layout (e.g., nasl/common/foo.nasl)"
        ),
    )
    parser.add_argument(
        "output_file",
        type=file_type,
        help=(
            "Path to the file where affected scripts will be written in relative "
            "feed layout (e.g., gsf/2020/foo.nasl)"
        ),
    )
    parser.add_argument(
        "--max-distance",
        "-d",
        type=int,
        default=None,
        help="Maximum dependency distance to follow",
    )

    args = parser.parse_args()

    run(
        args.feed_root,
        args.input_file,
        args.output_file,
        args.max_distance,
    )


if __name__ == "__main__":
    main()

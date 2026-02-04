# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG


import argparse
from pathlib import Path

import networkx as nx

from troubadix.argparser import directory_type_existing, file_type, file_type_existing

from .graph_builder import create_graph, get_feed
from .models import Feed


def run(
    root: Path,
    input_file: Path,
    output_file: Path,
    feed: Feed = Feed.COMMON,
    max_distance: int = None,
):
    graph = create_graph(get_feed(root, feed))
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

        # Simple prefix stripping to match node names
        path = Path(line)
        parts = list(path.parts)
        if parts and parts[0] == "nasl":
            parts.pop(0)
        if parts and (parts[0] == "common" or parts[0] == feed.value):
            parts.pop(0)

        name = str(Path(*parts))

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
        description="Find scripts affected by changes based on dependency graph."
    )
    parser.add_argument(
        "root",
        type=directory_type_existing,
        help="Root directory of the NASL repository",
    )
    parser.add_argument(
        "input_file",
        type=file_type_existing,
        help="Path to the file containing the list of changed scripts",
    )
    parser.add_argument(
        "output_file",
        type=file_type,
        help="Path to the file where affected scripts will be written",
    )
    parser.add_argument(
        "feed",
        type=Feed,
        choices=Feed,
        nargs="?",
        default=Feed.COMMON,
        help="Feed selection (e.g., common, 22.04)",
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
        args.root,
        args.input_file,
        args.output_file,
        args.feed,
        args.max_distance,
    )


if __name__ == "__main__":
    main()

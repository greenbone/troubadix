# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG

import argparse
import re
from pathlib import Path

import networkx as nx

from troubadix.helper import CURRENT_ENCODING
from troubadix.plugins.dependencies import split_dependencies

INCLUDE_PATTERN = re.compile(
    r"include\s*\(\s*(?P<quote>[\'\"])" r"(?P<value>.*?)(?P=quote)\s*\)\s*;"
)
DEPENDENCY_PATTERN = re.compile(r"script_dependencies\s*\(\s*(?P<value>.*?)\)", re.DOTALL)
NASL_EXTENSIONS = (".nasl", ".inc")


def create_graph_from_root(root: Path) -> nx.DiGraph:
    graph = nx.DiGraph()
    root = Path(root)

    for path in root.rglob("*"):
        if path.suffix not in NASL_EXTENSIONS or not path.is_file():
            continue
        content = path.read_text(encoding=CURRENT_ENCODING)
        name = str(path.relative_to(root))
        graph.add_node(name)

        for m in INCLUDE_PATTERN.finditer(content):
            graph.add_edge(name, m.group("value"))

        for m in DEPENDENCY_PATTERN.finditer(content):
            dep_list = split_dependencies(m.group("value"))
            for dep in dep_list:
                graph.add_edge(name, dep)

    return graph


def run(root: Path, input_file: Path, output_file: Path, max_distance: int = None):
    root = Path(root)
    graph = create_graph_from_root(root)

    changed_files = input_file.read_text().splitlines()
    affected = set()

    rev_graph = graph.reverse() if max_distance is not None else None

    for line in changed_files:
        line = line.strip()
        if not line:
            continue

        path = Path(line)
        parts = list(path.parts)
        # normalize inputs like 'nasl/common/..' or 'nasl/21.04/..' to names relative to root.
        if parts and parts[0] == "nasl":
            parts.pop(0)
        if parts and parts[0] in ("common", "21.04", "22.04"):
            parts.pop(0)

        name = str(Path(*parts))

        if name in graph:
            affected.add(name)
            if max_distance is None:
                affected.update(nx.ancestors(graph, name))
            else:
                lengths = nx.single_source_shortest_path_length(
                    rev_graph, name, cutoff=max_distance
                )
                affected.update(lengths.keys())

    if affected:
        output_file.write_text("\n".join(sorted(affected)) + "\n")
    else:
        output_file.write_text("")


def main():
    parser = argparse.ArgumentParser(description="Find scripts affected by changes.")
    parser.add_argument("root", help="Root directory where NASL files live")
    parser.add_argument("input_file", help="File with changed filenames")
    parser.add_argument("output_file", help="File to write affected scripts")
    parser.add_argument("--max-distance", "-d", type=int, default=None)

    args = parser.parse_args()
    run(Path(args.root), Path(args.input_file), Path(args.output_file), args.max_distance)


if __name__ == "__main__":
    main()
